package main

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type renameDeviceRequest struct {
	Name string `json:"name"`
}

func (a *API) renameMyDevice(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	deviceID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || deviceID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_device_id"})
		return
	}

	var in renameDeviceRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "device_name_must_be_1_to_64_bytes",
		})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var d device
	err = tx.QueryRow(r.Context(),
		`UPDATE devices
		 SET name = $1
		 WHERE id = $2
		   AND user_id = $3
		   AND revoked_at IS NULL
		 RETURNING id, name, platform, public_key, created_at,
		           last_seen_at, revoked_at`,
		in.Name, deviceID, userID,
	).Scan(
		&d.ID,
		&d.Name,
		&d.Platform,
		&d.PublicKey,
		&d.CreatedAt,
		&d.LastSeenAt,
		&d.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "device_not_found_or_revoked",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, userID, "rename_device", "device", d.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	writeJSON(w, http.StatusOK, d)
}
