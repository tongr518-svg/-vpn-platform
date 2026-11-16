package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type createInviteRequest struct {
	MaxUses   int        `json:"max_uses"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type inviteRecord struct {
	ID        int64      `json:"id"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

// authorizeInvite locks a valid database invite until the registration transaction
// commits. A zero ID means the legacy code was accepted during bootstrap.
func (a *API) authorizeInvite(ctx context.Context, tx pgx.Tx, code string) (int64, bool, error) {
	if code == "" {
		return 0, false, nil
	}

	sum := sha256.Sum256([]byte(code))
	var inviteID int64
	err := tx.QueryRow(ctx,
		`SELECT id FROM invite_codes
		 WHERE code_hash = $1
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > NOW())
		   AND uses < max_uses
		 FOR UPDATE`,
		sum[:],
	).Scan(&inviteID)
	if err == nil {
		return inviteID, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, err
	}

	if len(code) == len(a.inviteCode) && subtle.ConstantTimeCompare([]byte(code), []byte(a.inviteCode)) == 1 {
		var adminExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`,
		).Scan(&adminExists); err != nil {
			return 0, false, err
		}
		if !adminExists {
			return 0, true, nil
		}
	}
	return 0, false, nil
}

func (a *API) adminCreateInvite(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	var in createInviteRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.MaxUses == 0 {
		in.MaxUses = 1
	}
	if in.MaxUses < 1 || in.MaxUses > 100000 ||
		(in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now())) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_invite"})
		return
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	code := base64.RawURLEncoding.EncodeToString(randomBytes)
	codeHash := sha256.Sum256([]byte(code))

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var invite inviteRecord
	err = tx.QueryRow(r.Context(),
		`INSERT INTO invite_codes (code_hash, created_by, max_uses, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, max_uses, uses, expires_at, created_at`,
		codeHash[:], actorID, in.MaxUses, in.ExpiresAt,
	).Scan(&invite.ID, &invite.MaxUses, &invite.Uses, &invite.ExpiresAt, &invite.CreatedAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	invite.Status = "active"
	if err := insertAudit(r, tx, actorID, "create_invite_code", "invite_code", invite.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"invite": invite, "code": code})
}

func (a *API) adminListInvites(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT id, max_uses, uses, expires_at, created_at,
		        CASE
		          WHEN revoked_at IS NOT NULL THEN 'revoked'
		          WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
		          WHEN uses >= max_uses THEN 'exhausted'
		          ELSE 'active'
		        END AS status
		 FROM invite_codes
		 ORDER BY created_at DESC, id DESC
		 LIMIT 500`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	invites := make([]inviteRecord, 0)
	for rows.Next() {
		var invite inviteRecord
		if err := rows.Scan(&invite.ID, &invite.MaxUses, &invite.Uses, &invite.ExpiresAt, &invite.CreatedAt, &invite.Status); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		invites = append(invites, invite)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, invites)
}

func (a *API) adminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	inviteID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || inviteID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_invite_id"})
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
		`UPDATE invite_codes SET revoked_at = NOW()
		 WHERE id = $1 AND revoked_at IS NULL
		 RETURNING id`,
		inviteID,
	).Scan(&revokedID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite_not_found_or_already_revoked"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "revoke_invite_code", "invite_code", revokedID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
