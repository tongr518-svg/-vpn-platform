package main

import (
	"net/http"
	"time"
)

type userSubscriptionRecord struct {
	ID        int64     `json:"id"`
	PlanID    int64     `json:"plan_id"`
	PlanName  string    `json:"plan_name"`
	Status    string    `json:"status"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *API) listMySubscriptions(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT s.id, s.plan_id, p.name,
		        CASE
		          WHEN s.status = 'cancelled' THEN 'cancelled'
		          WHEN s.status = 'expired' OR s.ends_at <= NOW() THEN 'expired'
		          WHEN s.starts_at > NOW() THEN 'scheduled'
		          ELSE 'active'
		        END AS display_status,
	        s.starts_at, s.ends_at, s.created_at
		 FROM subscriptions s
		 JOIN plans p ON p.id = s.plan_id
		 WHERE s.user_id = $1
		 ORDER BY s.created_at DESC, s.id DESC
		 LIMIT 100`,
		userID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	subscriptions := make([]userSubscriptionRecord, 0)
	for rows.Next() {
		var item userSubscriptionRecord
		if err := rows.Scan(
			&item.ID,
			&item.PlanID,
			&item.PlanName,
			&item.Status,
			&item.StartsAt,
			&item.EndsAt,
			&item.CreatedAt,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		subscriptions = append(subscriptions, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	writeJSON(w, http.StatusOK, subscriptions)
}
