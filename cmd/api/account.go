package main

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (a *API) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var in changePasswordRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.NewPassword) < 12 || len(in.NewPassword) > 72 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "new_password_must_be_12_to_72_bytes",
		})
		return
	}
	if in.NewPassword == in.CurrentPassword {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_password_must_differ"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var passwordHash, status string
	err = tx.QueryRow(r.Context(),
		`SELECT password_hash, status
		 FROM users
		 WHERE id = $1
		 FOR UPDATE`,
		userID,
	).Scan(&passwordHash, &status)
	if err != nil || status != "active" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(in.CurrentPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_current_password"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE users
		 SET password_hash = $1,
		     token_version = token_version + 1
		 WHERE id = $2`,
		string(newHash), userID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	if err := insertAudit(r, tx, userID, "change_password", "user", userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeMySessions(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var status string
	err = tx.QueryRow(r.Context(),
		`SELECT status FROM users WHERE id = $1 FOR UPDATE`,
		userID,
	).Scan(&status)
	if err != nil || status != "active" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	if _, err := tx.Exec(r.Context(),
		`UPDATE users
		 SET token_version = token_version + 1
		 WHERE id = $1`,
		userID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, userID, "revoke_sessions", "user", userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
