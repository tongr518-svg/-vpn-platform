package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type adminSubscription struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Email     string    `json:"email"`
	PlanID    int64     `json:"plan_id"`
	PlanName  string    `json:"plan_name"`
	Status    string    `json:"status"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *API) adminListSubscriptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT s.id, s.user_id, u.email, s.plan_id, p.name,
		        CASE
		          WHEN s.status = 'active' AND s.ends_at <= NOW() THEN 'expired'
	          ELSE s.status
	        END,
	        s.starts_at, s.ends_at, s.created_at
		 FROM subscriptions s
		 JOIN users u ON u.id = s.user_id
		 JOIN plans p ON p.id = s.plan_id
		 ORDER BY s.created_at DESC
		 LIMIT 500`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	subscriptions := make([]adminSubscription, 0)
	for rows.Next() {
		var s adminSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.Email, &s.PlanID, &s.PlanName,
			&s.Status, &s.StartsAt, &s.EndsAt, &s.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		subscriptions = append(subscriptions, s)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, subscriptions)
}

func (a *API) adminCancelSubscription(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	subscriptionID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || subscriptionID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_subscription_id"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var cancelledID int64
	err = tx.QueryRow(r.Context(),
		`UPDATE subscriptions
		 SET status = 'cancelled'
		 WHERE id = $1 AND status = 'active' AND ends_at > NOW()
		 RETURNING id`,
		subscriptionID,
	).Scan(&cancelledID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_not_active"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "cancel_subscription", "subscription", cancelledID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
