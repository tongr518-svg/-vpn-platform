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
	ID               int64      `json:"id"`
	Name             string     `json:"name"`
	Region           string     `json:"region"`
	Status           string     `json:"status"`
	HealthStatus     string     `json:"health_status"`
	Capacity         int        `json:"capacity"`
	AssignedDevices  int        `json:"assigned_device_count"`
	CreatedAt        time.Time  `json:"created_at"`
	LastHeartbeatAt  *time.Time `json:"last_heartbeat_at,omitempty"`
	CredentialActive bool       `json:"credential_active"`
}

type createNodeRequest struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	Capacity int    `json:"capacity"`
}

type updateNodeRequest struct {
	Name     *string `json:"name"`
	Region   *string `json:"region"`
	Capacity *int    `json:"capacity"`
}

type setNodeStatusRequest struct {
	Status string `json:"status"`
}

const nodeSelectColumns = `id, name, region, status, capacity, created_at,
	last_heartbeat_at,
	EXISTS (SELECT 1 FROM node_credentials c
	        WHERE c.node_id = nodes.id AND c.revoked_at IS NULL),
	CASE WHEN last_heartbeat_at > NOW() - INTERVAL '90 seconds'
	     THEN 'online' ELSE 'offline' END,
	(SELECT COUNT(*)::int FROM node_device_assignments a
	 JOIN devices d ON d.id = a.device_id
	 WHERE a.node_id = nodes.id AND d.revoked_at IS NULL)`

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
	if !validNodeMetadata(in.Name, in.Region, in.Capacity) {
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
		`INSERT INTO nodes (name, region, capacity)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, region, status, capacity, created_at, last_heartbeat_at`,
		in.Name, in.Region, in.Capacity,
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
	writeJSON(w, http.StatusCreated, map[string]any{"node": node, "credential": credential})
}

func (a *API) adminListNodes(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT `+nodeSelectColumns+`
		 FROM nodes
		 ORDER BY created_at DESC, id DESC
		 LIMIT 500`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	nodes := make([]nodeRecord, 0)
	for rows.Next() {
		var node nodeRecord
		if err := rows.Scan(
			&node.ID, &node.Name, &node.Region, &node.Status,
			&node.Capacity, &node.CreatedAt, &node.LastHeartbeatAt,
			&node.CredentialActive, &node.HealthStatus, &node.AssignedDevices,
		); err != nil {
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
	if in.Name == nil && in.Region == nil && in.Capacity == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty_node_update"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var name, region string
	var capacity, assignedDevices int
	err = tx.QueryRow(r.Context(),
		`SELECT n.name, n.region, n.capacity,
		        (SELECT COUNT(*)::int FROM node_device_assignments a
		         JOIN devices d ON d.id = a.device_id
		         WHERE a.node_id = n.id AND d.revoked_at IS NULL)
		 FROM nodes n WHERE n.id = $1 FOR UPDATE`, nodeID,
	).Scan(&name, &region, &capacity, &assignedDevices)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if in.Region != nil {
		region = strings.TrimSpace(*in.Region)
	}
	if in.Capacity != nil {
		capacity = *in.Capacity
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

	var node nodeRecord
	err = tx.QueryRow(r.Context(),
		`UPDATE nodes SET name = $1, region = $2, capacity = $3
		 WHERE id = $4
		 RETURNING id, name, region, status, capacity, created_at,
		           last_heartbeat_at,
		           EXISTS (SELECT 1 FROM node_credentials c
		                   WHERE c.node_id = nodes.id AND c.revoked_at IS NULL),
		           CASE WHEN last_heartbeat_at > NOW() - INTERVAL '90 seconds'
		                THEN 'online' ELSE 'offline' END,
		           (SELECT COUNT(*)::int FROM node_device_assignments a
		            JOIN devices d ON d.id = a.device_id
		            WHERE a.node_id = nodes.id AND d.revoked_at IS NULL)`,
		name, region, capacity, nodeID,
	).Scan(
		&node.ID, &node.Name, &node.Region, &node.Status, &node.Capacity,
		&node.CreatedAt, &node.LastHeartbeatAt, &node.CredentialActive,
		&node.HealthStatus, &node.AssignedDevices,
	)
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

	var node nodeRecord
	err = tx.QueryRow(r.Context(),
		`UPDATE nodes SET status = $1 WHERE id = $2
		 RETURNING id, name, region, status, capacity, created_at,
		           last_heartbeat_at,
		           EXISTS (SELECT 1 FROM node_credentials c
		                   WHERE c.node_id = nodes.id AND c.revoked_at IS NULL),
		           CASE WHEN last_heartbeat_at > NOW() - INTERVAL '90 seconds'
		                THEN 'online' ELSE 'offline' END,
		           (SELECT COUNT(*)::int FROM node_device_assignments a
		            JOIN devices d ON d.id = a.device_id
		            WHERE a.node_id = nodes.id AND d.revoked_at IS NULL)`,
		in.Status, nodeID,
	).Scan(
		&node.ID, &node.Name, &node.Region, &node.Status, &node.Capacity,
		&node.CreatedAt, &node.LastHeartbeatAt, &node.CredentialActive,
		&node.HealthStatus, &node.AssignedDevices,
	)
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
