package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type adminDevice struct {
	ID                  int64      `json:"id"`
	Name                string     `json:"name"`
	Platform            string     `json:"platform"`
	CreatedAt           time.Time  `json:"created_at"`
	Revoked             bool       `json:"revoked"`
	AssignedNodeID      *int64     `json:"assigned_node_id,omitempty"`
	AssignedNodeName    string     `json:"assigned_node_name,omitempty"`
	AssignedNodeStatus  string     `json:"assigned_node_status,omitempty"`
	AssignedNodeHealth  string     `json:"assigned_node_health_status,omitempty"`
	AssignmentCreatedAt *time.Time `json:"assignment_created_at,omitempty"`
}

func (a *API) adminListUserDevices(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || userID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}

	var exists bool
	if err := a.db.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT d.id, d.name, d.platform, d.created_at, d.revoked_at IS NOT NULL,
		        n.id, COALESCE(n.name, ''), COALESCE(n.status, ''),
		        CASE WHEN n.id IS NULL THEN ''
		             WHEN n.last_heartbeat_at > NOW() - INTERVAL '90 seconds' THEN 'online'
		             ELSE 'offline' END,
	        a.assigned_at
		 FROM devices d
		 LEFT JOIN node_device_assignments a ON a.device_id = d.id
		 LEFT JOIN nodes n ON n.id = a.node_id
		 WHERE d.user_id = $1
		 ORDER BY d.created_at DESC LIMIT 500`,
		userID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	devices := make([]adminDevice, 0)
	for rows.Next() {
		var d adminDevice
		if err := rows.Scan(
			&d.ID, &d.Name, &d.Platform, &d.CreatedAt, &d.Revoked,
			&d.AssignedNodeID, &d.AssignedNodeName, &d.AssignedNodeStatus,
			&d.AssignedNodeHealth, &d.AssignmentCreatedAt,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (a *API) adminRevokeUserDevice(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || userID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}
	deviceID, err := strconv.ParseInt(r.PathValue("deviceID"), 10, 64)
	if err != nil || deviceID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_device_id"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var revokedID int64
	err = tx.QueryRow(r.Context(),
		`UPDATE devices SET revoked_at = NOW()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		 RETURNING id`,
		deviceID, userID,
	).Scan(&revokedID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_found_or_already_revoked"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "admin_revoke_device", "device", revokedID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
