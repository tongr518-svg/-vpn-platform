package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type assignDeviceRequest struct {
	NodeID int64 `json:"node_id"`
}

type deviceAssignmentRecord struct {
	DeviceID   int64     `json:"device_id"`
	NodeID     int64     `json:"node_id"`
	NodeName   string    `json:"node_name"`
	Status     string    `json:"status"`
	AssignedAt time.Time `json:"assigned_at"`
}

func (a *API) adminAssignDeviceToNode(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	deviceID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || deviceID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_device_id"})
		return
	}
	var in assignDeviceRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.NodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	// Lock the device and its account so concurrent revocation/suspension cannot
	// race the eligibility checks. Every assignment path locks device before node.
	var ownerID int64
	var deviceActive bool
	var userStatus string
	err = tx.QueryRow(r.Context(),
		`SELECT d.user_id, d.revoked_at IS NULL, u.status
		 FROM devices d
		 JOIN users u ON u.id = d.user_id
		 WHERE d.id = $1
		 FOR UPDATE OF d, u`,
		deviceID,
	).Scan(&ownerID, &deviceActive, &userStatus)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if !deviceActive {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "device_revoked"})
		return
	}
	if userStatus != "active" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "user_not_active"})
		return
	}

	var alreadyAssigned bool
	if err := tx.QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM node_device_assignments WHERE device_id = $1)`, deviceID,
	).Scan(&alreadyAssigned); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if alreadyAssigned {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "device_already_assigned"})
		return
	}

	// Lock a currently valid subscription so cancellation waits for this
	// assignment transaction to finish.
	var subscriptionID int64
	err = tx.QueryRow(r.Context(),
		`SELECT id FROM subscriptions
		 WHERE user_id = $1
		   AND status = 'active'
		   AND starts_at <= NOW()
		   AND ends_at > NOW()
		 ORDER BY ends_at DESC
		 LIMIT 1
		 FOR UPDATE`,
		ownerID,
	).Scan(&subscriptionID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "active_subscription_required"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	var nodeStatus string
	var capacity int
	err = tx.QueryRow(r.Context(),
		`SELECT status, capacity FROM nodes WHERE id = $1 FOR UPDATE`, in.NodeID,
	).Scan(&nodeStatus, &capacity)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if nodeStatus != "active" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "node_not_assignable"})
		return
	}

	var assignedCount int
	err = tx.QueryRow(r.Context(),
		`SELECT COUNT(*)::int
		 FROM node_device_assignments a
		 JOIN devices d ON d.id = a.device_id
		 WHERE a.node_id = $1 AND d.revoked_at IS NULL`,
		in.NodeID,
	).Scan(&assignedCount)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if assignedCount >= capacity {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                 "node_capacity_reached",
			"assigned_device_count": assignedCount,
		})
		return
	}

	var assignment deviceAssignmentRecord
	err = tx.QueryRow(r.Context(),
		`INSERT INTO node_device_assignments (node_id, device_id)
		 VALUES ($1, $2)
		 RETURNING assigned_at`,
		in.NodeID, deviceID,
	).Scan(&assignment.AssignedAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	assignment.DeviceID = deviceID
	assignment.NodeID = in.NodeID
	err = tx.QueryRow(r.Context(), `SELECT name FROM nodes WHERE id = $1`, in.NodeID).Scan(&assignment.NodeName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	assignment.Status = nodeStatus
	if err := insertAudit(r, tx, actorID, "assign_device_node", "device", deviceID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, assignment)
}

func (a *API) adminUnassignDeviceFromNode(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	deviceID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
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

	var lockedDeviceID int64
	err = tx.QueryRow(r.Context(), `SELECT id FROM devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&lockedDeviceID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	var nodeID int64
	err = tx.QueryRow(r.Context(),
		`SELECT node_id FROM node_device_assignments WHERE device_id = $1`, deviceID,
	).Scan(&nodeID)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_assigned"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	var lockedNodeID int64
	err = tx.QueryRow(r.Context(), `SELECT id FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&lockedNodeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	result, err := tx.Exec(r.Context(), `DELETE FROM node_device_assignments WHERE device_id = $1`, deviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if result.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_assigned"})
		return
	}
	if err := insertAudit(r, tx, actorID, "unassign_device_node", "device", deviceID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
