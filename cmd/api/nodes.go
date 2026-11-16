package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type nodeRecord struct {
	ID                     int64      `json:"id"`
	Name                   string     `json:"name"`
	Region                 string     `json:"region"`
	Status                 string     `json:"status"`
	HealthStatus           string     `json:"health_status"`
	Capacity               int        `json:"capacity"`
	AssignedDevices        int        `json:"assigned_device_count"`
	TunnelCIDR             string     `json:"tunnel_cidr"`
	AddressPoolSize        int64      `json:"address_pool_size"`
	AddressAllocated       int64      `json:"address_allocated"`
	AddressAvailable       int64      `json:"address_available"`
	DryRunStatus           string     `json:"dry_run_status"`
	DryRunBaseVersion      int64      `json:"dry_run_confirmed_version"`
	DryRunCandidateVersion int64      `json:"dry_run_candidate_version"`
	DryRunAdded            int        `json:"dry_run_added_count"`
	DryRunChanged          int        `json:"dry_run_changed_count"`
	DryRunRemoved          int        `json:"dry_run_removed_count"`
	DryRunNetworkChanged   bool       `json:"dry_run_network_changed"`
	DryRunErrors           []string   `json:"dry_run_validation_errors"`
	DryRunAt               *time.Time `json:"dry_run_at,omitempty"`
	DesiredVersion         int64      `json:"desired_config_version"`
	AckVersion             int64      `json:"acknowledged_config_version"`
	SyncPending            bool       `json:"sync_pending"`
	LastSyncAt             *time.Time `json:"last_sync_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	LastHeartbeatAt        *time.Time `json:"last_heartbeat_at,omitempty"`
	CredentialActive       bool       `json:"credential_active"`
}

type createNodeRequest struct {
	Name       string `json:"name"`
	Region     string `json:"region"`
	Capacity   int    `json:"capacity"`
	TunnelCIDR string `json:"tunnel_cidr"`
}

type updateNodeRequest struct {
	Name       *string `json:"name"`
	Region     *string `json:"region"`
	Capacity   *int    `json:"capacity"`
	TunnelCIDR *string `json:"tunnel_cidr"`
}

type setNodeStatusRequest struct {
	Status string `json:"status"`
}

const nodeSelectColumns = `id, name, region, status, capacity, created_at,
	last_heartbeat_at,
	COALESCE(tunnel_cidr::text, ''),
	EXISTS (SELECT 1 FROM node_credentials c
	        WHERE c.node_id = nodes.id AND c.revoked_at IS NULL),
	CASE WHEN last_heartbeat_at > NOW() - INTERVAL '90 seconds'
	     THEN 'online' ELSE 'offline' END,
	(SELECT COUNT(*)::int FROM node_device_assignments a
	 JOIN devices d ON d.id = a.device_id
	 WHERE a.node_id = nodes.id AND d.revoked_at IS NULL),
	(SELECT COUNT(*)::bigint FROM node_tunnel_addresses ta WHERE ta.node_id = nodes.id),
	COALESCE((SELECT status FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 'not_run'),
	COALESCE((SELECT confirmed_version FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 0),
	COALESCE((SELECT candidate_version FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 0),
	COALESCE((SELECT added_count FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 0),
	COALESCE((SELECT changed_count FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 0),
	COALESCE((SELECT removed_count FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), 0),
	COALESCE((SELECT network_changed FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), FALSE),
	COALESCE((SELECT validation_errors FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id), ARRAY[]::text[]),
	(SELECT created_at FROM node_config_dry_runs dr WHERE dr.node_id = nodes.id),
	desired_config_version, acknowledged_config_version,
	(acknowledged_config_version < desired_config_version), last_sync_at`

func scanNodeRecord(row interface{ Scan(...any) error }) (nodeRecord, error) {
	var node nodeRecord
	err := row.Scan(
		&node.ID, &node.Name, &node.Region, &node.Status, &node.Capacity,
		&node.CreatedAt, &node.LastHeartbeatAt, &node.TunnelCIDR,
		&node.CredentialActive, &node.HealthStatus, &node.AssignedDevices,
		&node.AddressAllocated, &node.DryRunStatus, &node.DryRunBaseVersion,
		&node.DryRunCandidateVersion, &node.DryRunAdded, &node.DryRunChanged,
		&node.DryRunRemoved, &node.DryRunNetworkChanged, &node.DryRunErrors, &node.DryRunAt,
		&node.DesiredVersion, &node.AckVersion,
		&node.SyncPending, &node.LastSyncAt,
	)
	if err != nil {
		return node, err
	}
	if node.TunnelCIDR != "" {
		if _, size, err := parseTunnelPrefix(node.TunnelCIDR); err == nil {
			node.AddressPoolSize = int64(size)
			node.AddressAvailable = int64(size) - node.AddressAllocated
		}
	}
	return node, nil
}

func generateNodeCredential() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	credential := "node_" + base64.RawURLEncoding.EncodeToString(raw[:])
	return credential, sha256.Sum256([]byte(credential)), nil
}

func validNodeMetadata(name, region string, capacity int) bool {
	return name != "" && len(name) <= 100 && region != "" && len(region) <= 80 && capacity > 0 && capacity <= 1_000_000
}

func (a *API) adminCreateNode(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	var in createNodeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Region = strings.TrimSpace(in.Region)
	in.TunnelCIDR = strings.TrimSpace(in.TunnelCIDR)
	prefix, err := parseTunnelPrefixForCapacity(in.TunnelCIDR, in.Capacity)
	if !validNodeMetadata(in.Name, in.Region, in.Capacity) || err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node"})
		return
	}

	credential, tokenHash, err := generateNodeCredential()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var node nodeRecord
	err = tx.QueryRow(r.Context(),
		`INSERT INTO nodes (name, region, capacity, tunnel_cidr)
		 VALUES ($1, $2, $3, $4::cidr)
		 RETURNING id, name, region, status, capacity, created_at, last_heartbeat_at`,
		in.Name, in.Region, in.Capacity, prefix.String(),
	).Scan(&node.ID, &node.Name, &node.Region, &node.Status, &node.Capacity, &node.CreatedAt, &node.LastHeartbeatAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`INSERT INTO node_credentials (node_id, token_hash) VALUES ($1, $2)`,
		node.ID, tokenHash[:],
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "create_node", "node", node.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	node.CredentialActive = true
	node.HealthStatus = "offline"
	node.TunnelCIDR = prefix.String()
	_, poolSize, _ := parseTunnelPrefix(prefix.String())
	node.AddressPoolSize = int64(poolSize)
	node.AddressAvailable = int64(poolSize)
	node.DryRunStatus = "not_run"
	node.DryRunErrors = []string{}
	writeJSON(w, http.StatusCreated, map[string]any{"node": node, "credential": credential})
}

func (a *API) adminListNodes(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT `+nodeSelectColumns+`
		 FROM nodes
		 ORDER BY nodes.created_at DESC, nodes.id DESC
		 LIMIT 500`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	nodes := make([]nodeRecord, 0)
	for rows.Next() {
		node, err := scanNodeRecord(rows)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (a *API) adminUpdateNode(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}
	var in updateNodeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Name == nil && in.Region == nil && in.Capacity == nil && in.TunnelCIDR == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty_node_update"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var name, region, tunnelCIDR, originalTunnelCIDR string
	var capacity, assignedDevices int
	err = tx.QueryRow(r.Context(),
		`SELECT n.name, n.region, n.capacity, COALESCE(n.tunnel_cidr::text, ''),
		        (SELECT COUNT(*)::int FROM node_device_assignments a
		         JOIN devices d ON d.id = a.device_id
		         WHERE a.node_id = n.id AND d.revoked_at IS NULL)
		 FROM nodes n WHERE n.id = $1 FOR UPDATE`, nodeID,
	).Scan(&name, &region, &capacity, &tunnelCIDR, &assignedDevices)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	originalTunnelCIDR = tunnelCIDR
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if in.Region != nil {
		region = strings.TrimSpace(*in.Region)
	}
	if in.Capacity != nil {
		capacity = *in.Capacity
	}
	if in.TunnelCIDR != nil {
		tunnelCIDR = strings.TrimSpace(*in.TunnelCIDR)
	}
	if !validNodeMetadata(name, region, capacity) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node"})
		return
	}
	if capacity < assignedDevices {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                 "node_capacity_below_assigned_devices",
			"assigned_device_count": assignedDevices,
		})
		return
	}
	if tunnelCIDR != "" {
		if _, err := parseTunnelPrefixForCapacity(tunnelCIDR, capacity); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_tunnel_cidr_or_capacity"})
			return
		}
	}
	if in.TunnelCIDR != nil && tunnelCIDR != originalTunnelCIDR {
		var reserved int64
		if err := tx.QueryRow(r.Context(),
			`SELECT
			   (SELECT COUNT(*) FROM node_device_assignments WHERE node_id = $1) +
			   (SELECT COUNT(*) FROM node_tunnel_addresses WHERE node_id = $1)`,
			nodeID,
		).Scan(&reserved); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		if reserved > 0 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot_change_tunnel_cidr_while_assignments_or_addresses_reserved"})
			return
		}
	}

	if _, err := tx.Exec(r.Context(),
		`UPDATE nodes SET name = $1, region = $2, capacity = $3, tunnel_cidr = NULLIF($4, '')::cidr
		 WHERE id = $5`, name, region, capacity, tunnelCIDR, nodeID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	node, err := scanNodeRecord(tx.QueryRow(r.Context(), `SELECT `+nodeSelectColumns+` FROM nodes WHERE id = $1`, nodeID))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "update_node", "node", node.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (a *API) adminSetNodeStatus(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}
	var in setNodeStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	switch in.Status {
	case "active", "maintenance", "disabled":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_status"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	_, err = tx.Exec(r.Context(), `UPDATE nodes SET status = $1 WHERE id = $2`, in.Status, nodeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	node, err := scanNodeRecord(tx.QueryRow(r.Context(), `SELECT `+nodeSelectColumns+` FROM nodes WHERE id = $1`, nodeID))
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "set_node_status", "node", node.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (a *API) adminRotateNodeCredential(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}
	credential, tokenHash, err := generateNodeCredential()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	var lockedID int64
	err = tx.QueryRow(r.Context(), `SELECT id FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&lockedID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE node_credentials SET revoked_at = NOW()
		 WHERE node_id = $1 AND revoked_at IS NULL`, nodeID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`INSERT INTO node_credentials (node_id, token_hash) VALUES ($1, $2)`,
		nodeID, tokenHash[:],
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "rotate_node_credential", "node", nodeID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"credential": credential})
}

func (a *API) adminRevokeNodeCredential(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	var lockedID int64
	err = tx.QueryRow(r.Context(), `SELECT id FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&lockedID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	result, err := tx.Exec(r.Context(),
		`UPDATE node_credentials SET revoked_at = NOW()
		 WHERE node_id = $1 AND revoked_at IS NULL`, nodeID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if result.RowsAffected() > 0 {
		if err := insertAudit(r, tx, actorID, "revoke_node_credential", "node", nodeID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) nodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	credential := strings.TrimPrefix(header, prefix)
	if len(credential) < len("node_")+32 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	tokenHash := sha256.Sum256([]byte(credential))
	var nodeID int64
	err := a.db.QueryRow(r.Context(),
		`UPDATE nodes
		 SET last_heartbeat_at = NOW()
		 FROM node_credentials c
		 WHERE c.node_id = nodes.id
		   AND c.token_hash = $1
		   AND c.revoked_at IS NULL
		   AND nodes.status IN ('active', 'maintenance')
		 RETURNING nodes.id`,
		tokenHash[:],
	).Scan(&nodeID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
