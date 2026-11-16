package main

import (
	"context"
	"crypto/sha256"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/nodeprotocol"
)

type nodeConfigDevice = nodeprotocol.Device
type nodeConfigSnapshot = nodeprotocol.Snapshot

type acknowledgeNodeConfigRequest struct {
	Version int64 `json:"version"`
}

type nodeConfigDryRunRequest struct {
	ConfirmedSnapshot nodeConfigSnapshot `json:"confirmed_snapshot"`
}

type nodeConfigDryRunSummary struct {
	ConfirmedVersion int64     `json:"confirmed_version"`
	CandidateVersion int64     `json:"candidate_version"`
	CandidateDigest  string    `json:"candidate_digest"`
	Status           string    `json:"status"`
	AddedCount       int       `json:"added_count"`
	ChangedCount     int       `json:"changed_count"`
	RemovedCount     int       `json:"removed_count"`
	NetworkChanged   bool      `json:"network_changed"`
	ValidationErrors []string  `json:"validation_errors"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
}

// recordNodeConfigChange appends the outbox event and increments the desired
// state version in the caller's transaction.
func recordNodeConfigChange(
	ctx context.Context,
	tx pgx.Tx,
	nodeID int64,
	eventType string,
	deviceID int64,
) (int64, error) {
	var version int64
	if err := tx.QueryRow(ctx,
		`UPDATE nodes
		 SET desired_config_version = desired_config_version + 1
		 WHERE id = $1
		 RETURNING desired_config_version`,
		nodeID,
	).Scan(&version); err != nil {
		return 0, err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO node_config_outbox (node_id, version, event_type, device_id)
		 VALUES ($1, $2, $3, $4)`,
		nodeID, version, eventType, deviceID,
	)
	return version, err
}

func nodeCredentialHash(r *http.Request) ([32]byte, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return [32]byte{}, false
	}
	credential := strings.TrimPrefix(header, prefix)
	if len(credential) < len("node_")+32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(credential)), true
}

func nodeIDForCredential(ctx context.Context, tx pgx.Tx, tokenHash [32]byte) (int64, int64, error) {
	var nodeID, desiredVersion int64
	err := tx.QueryRow(ctx,
		`SELECT n.id, n.desired_config_version
		 FROM nodes n
		 JOIN node_credentials c ON c.node_id = n.id
		 WHERE c.token_hash = $1
		   AND c.revoked_at IS NULL
		   AND n.status IN ('active', 'maintenance')`,
		tokenHash[:],
	).Scan(&nodeID, &desiredVersion)
	return nodeID, desiredVersion, err
}

func loadNodeConfigSnapshot(ctx context.Context, tx pgx.Tx, nodeID, version int64) (nodeConfigSnapshot, error) {
	snapshot := nodeConfigSnapshot{NodeID: nodeID, Version: version, Devices: make([]nodeConfigDevice, 0)}
	var tunnelCIDR string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(tunnel_cidr::text, '') FROM nodes WHERE id = $1`, nodeID,
	).Scan(&tunnelCIDR); err != nil {
		return nodeConfigSnapshot{}, err
	}
	snapshot.TunnelCIDR = tunnelCIDR
	if tunnelCIDR != "" {
		prefix, _, err := parseTunnelPrefix(tunnelCIDR)
		if err == nil {
			snapshot.GatewayAddress = prefixAddress(prefix, 1).String()
		}
	}
	rows, err := tx.Query(ctx,
		`SELECT d.id, d.public_key, d.platform, a.assigned_at,
		        COALESCE(host(ta.address), ''), d.revoked_at IS NOT NULL
		 FROM node_device_assignments a
		 JOIN devices d ON d.id = a.device_id
		 LEFT JOIN node_tunnel_addresses ta
		   ON ta.node_id = a.node_id AND ta.device_id = a.device_id AND ta.state = 'assigned'
		 WHERE a.node_id = $1
		 ORDER BY d.id`,
		nodeID,
	)
	if err != nil {
		return nodeConfigSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item nodeConfigDevice
		if err := rows.Scan(&item.DeviceID, &item.PublicKey, &item.Platform, &item.AssignedAt, &item.TunnelAddress, &item.Revoked); err != nil {
			return nodeConfigSnapshot{}, err
		}
		snapshot.Devices = append(snapshot.Devices, item)
	}
	if err := rows.Err(); err != nil {
		return nodeConfigSnapshot{}, err
	}
	return snapshot, nil
}

func (a *API) nodeConfig(w http.ResponseWriter, r *http.Request) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Repeatable read keeps the version and the assigned-device list from one
	// consistent database snapshot while assignments may change concurrently.
	tx, err := a.db.BeginTx(r.Context(), pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var nodeID, version int64
	nodeID, version, err = nodeIDForCredential(r.Context(), tx, tokenHash)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	snapshot, err := loadNodeConfigSnapshot(r.Context(), tx, nodeID, version)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	_, _, _, validationErrors := validatePlannerSnapshot(snapshot, true, nil)
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "node_config_validation_failed", "validation_errors": validationErrors,
		})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, snapshot)
}

func (a *API) nodeConfigDryRun(w http.ResponseWriter, r *http.Request) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var in nodeConfigDryRunRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ConfirmedSnapshot.Version < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_confirmed_version"})
		return
	}

	tx, err := a.db.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	nodeID, desiredVersion, err := nodeIDForCredential(r.Context(), tx, tokenHash)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	var acknowledgedVersion int64
	if err := tx.QueryRow(r.Context(), `SELECT acknowledged_config_version FROM nodes WHERE id = $1`, nodeID).Scan(&acknowledgedVersion); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	candidate, err := loadNodeConfigSnapshot(r.Context(), tx, nodeID, desiredVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	digest, err := candidateSnapshotDigest(candidate)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	confirmed := in.ConfirmedSnapshot
	errors := make([]string, 0)
	if confirmed.NodeID != nodeID {
		errors = append(errors, "confirmed_node_id_mismatch")
	}
	if confirmed.Version != acknowledgedVersion {
		errors = append(errors, "confirmed_version_not_current")
	}
	plan, plannerErrors := planWireGuardDryRun(confirmed, candidate, nil)
	errors = append(errors, plannerErrors...)
	sort.Strings(errors)
	status := "valid"
	if len(errors) > 0 {
		status = "invalid"
	}
	summary := nodeConfigDryRunSummary{
		ConfirmedVersion: confirmed.Version,
		CandidateVersion: candidate.Version,
		CandidateDigest:  digest,
		Status:           status,
		ValidationErrors: errors,
	}
	if plan != nil {
		summary.AddedCount = len(plan.Added)
		summary.ChangedCount = len(plan.Changed)
		summary.RemovedCount = len(plan.Removed)
		summary.NetworkChanged = plan.NetworkChanged
	}
	if len(errors) > 0 {
		plan = nil
		summary.AddedCount = 0
		summary.ChangedCount = 0
		summary.RemovedCount = 0
		summary.NetworkChanged = false
	}
	if err := tx.QueryRow(r.Context(),
		`INSERT INTO node_config_dry_runs
		 (node_id, confirmed_version, candidate_version, status,
		  added_count, changed_count, removed_count, network_changed, validation_errors, candidate_digest)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (node_id) DO UPDATE SET
		   confirmed_version = EXCLUDED.confirmed_version,
		   candidate_version = EXCLUDED.candidate_version,
		   status = EXCLUDED.status,
		   added_count = EXCLUDED.added_count,
		   changed_count = EXCLUDED.changed_count,
		   removed_count = EXCLUDED.removed_count,
		   network_changed = EXCLUDED.network_changed,
		   validation_errors = EXCLUDED.validation_errors,
		   candidate_digest = EXCLUDED.candidate_digest,
		   created_at = NOW()
		 RETURNING created_at`,
		nodeID, summary.ConfirmedVersion, summary.CandidateVersion, summary.Status,
		summary.AddedCount, summary.ChangedCount, summary.RemovedCount, summary.NetworkChanged, summary.ValidationErrors, summary.CandidateDigest,
	).Scan(&summary.CreatedAt); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if plan == nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "dry_run_validation_failed", "dry_run": summary,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run": summary,
		"plan":    plan,
		"applied": false,
	})
}

func (a *API) acknowledgeNodeConfig(w http.ResponseWriter, r *http.Request) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var in acknowledgeNodeConfigRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Version < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config_version"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var nodeID, desiredVersion, acknowledgedVersion int64
	err = tx.QueryRow(r.Context(),
		`SELECT n.id, n.desired_config_version, n.acknowledged_config_version
		 FROM nodes n
		 JOIN node_credentials c ON c.node_id = n.id
		 WHERE c.token_hash = $1
		   AND c.revoked_at IS NULL
		   AND n.status IN ('active', 'maintenance')
		 FOR UPDATE OF n`,
		tokenHash[:],
	).Scan(&nodeID, &desiredVersion, &acknowledgedVersion)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if in.Version > desiredVersion {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "config_version_not_found"})
		return
	}
	if in.Version < acknowledgedVersion {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "config_version_behind_acknowledgment"})
		return
	}
	if in.Version > 0 {
		var exists bool
		if err := tx.QueryRow(r.Context(),
			`SELECT EXISTS (
			   SELECT 1 FROM node_config_outbox WHERE node_id = $1 AND version = $2
			)`,
			nodeID, in.Version,
		).Scan(&exists); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		if !exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "config_version_not_found"})
			return
		}
	}

	if _, err := tx.Exec(r.Context(),
		`UPDATE nodes
		 SET acknowledged_config_version = GREATEST(acknowledged_config_version, $1),
		     last_sync_at = NOW()
		 WHERE id = $2`,
		in.Version, nodeID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM node_tunnel_addresses
		 WHERE node_id = $1 AND state = 'releasing' AND release_version <= $2`,
		nodeID, in.Version,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE node_config_outbox
		 SET acknowledged_at = COALESCE(acknowledged_at, NOW())
		 WHERE node_id = $1 AND version <= $2`,
		nodeID, in.Version,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// addDeviceConfigOutboxForRevocation removes the now-invalid assignment and
// records the resulting desired-state change atomically with device revocation.
func addDeviceConfigOutboxForRevocation(ctx context.Context, tx pgx.Tx, deviceID int64) error {
	var nodeID int64
	err := tx.QueryRow(ctx,
		`DELETE FROM node_device_assignments
		 WHERE device_id = $1
		 RETURNING node_id`,
		deviceID,
	).Scan(&nodeID)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	version, err := recordNodeConfigChange(ctx, tx, nodeID, "device_revoked", deviceID)
	if err != nil {
		return err
	}
	return markTunnelAddressReleasing(ctx, tx, nodeID, deviceID, version)
}
