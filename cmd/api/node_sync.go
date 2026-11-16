package main

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type nodeConfigDevice struct {
	DeviceID   int64     `json:"device_id"`
	PublicKey  string    `json:"public_key"`
	Platform   string    `json:"platform"`
	AssignedAt time.Time `json:"assigned_at"`
}

type nodeConfigSnapshot struct {
	NodeID  int64              `json:"node_id"`
	Version int64              `json:"version"`
	Devices []nodeConfigDevice `json:"devices"`
}

type acknowledgeNodeConfigRequest struct {
	Version int64 `json:"version"`
}

// recordNodeConfigChange appends the outbox event and increments the desired
// state version in the caller's transaction.
func recordNodeConfigChange(
	ctx context.Context,
	tx pgx.Tx,
	nodeID int64,
	eventType string,
	deviceID int64,
) error {
	var version int64
	if err := tx.QueryRow(ctx,
		`UPDATE nodes
		 SET desired_config_version = desired_config_version + 1
		 WHERE id = $1
		 RETURNING desired_config_version`,
		nodeID,
	).Scan(&version); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO node_config_outbox (node_id, version, event_type, device_id)
		 VALUES ($1, $2, $3, $4)`,
		nodeID, version, eventType, deviceID,
	)
	return err
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

	var snapshot nodeConfigSnapshot
	snapshot.NodeID, snapshot.Version, err = nodeIDForCredential(r.Context(), tx, tokenHash)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	rows, err := tx.Query(r.Context(),
		`SELECT d.id, d.public_key, d.platform, a.assigned_at
		 FROM node_device_assignments a
		 JOIN devices d ON d.id = a.device_id
		 WHERE a.node_id = $1 AND d.revoked_at IS NULL
		 ORDER BY d.id`,
		snapshot.NodeID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	snapshot.Devices = make([]nodeConfigDevice, 0)
	for rows.Next() {
		var item nodeConfigDevice
		if err := rows.Scan(&item.DeviceID, &item.PublicKey, &item.Platform, &item.AssignedAt); err != nil {
			rows.Close()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		snapshot.Devices = append(snapshot.Devices, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	rows.Close()
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, snapshot)
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
	return recordNodeConfigChange(ctx, tx, nodeID, "device_revoked", deviceID)
}
