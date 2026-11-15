package main

import (
	"database/sql"
	"net/http"
	"time"
)

type auditLogRecord struct {
	ID          int64     `json:"id"`
	ActorUserID *int64    `json:"actor_user_id,omitempty"`
	ActorEmail  string    `json:"actor_email,omitempty"`
	Action      string    `json:"action"`
	TargetType  string    `json:"target_type"`
	TargetID    *string   `json:"target_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (a *API) adminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT l.id, l.actor_user_id, u.email,
		        l.action, l.target_type, l.target_id, l.created_at
		 FROM admin_audit_logs l
		 LEFT JOIN users u ON u.id = l.actor_user_id
		 ORDER BY l.id DESC
		 LIMIT 500`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	logs := make([]auditLogRecord, 0)
	for rows.Next() {
		var record auditLogRecord
		var actorID sql.NullInt64
		var actorEmail sql.NullString
		var targetID sql.NullString

		if err := rows.Scan(
			&record.ID,
			&actorID,
			&actorEmail,
			&record.Action,
			&record.TargetType,
			&targetID,
			&record.CreatedAt,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}

		if actorID.Valid {
			value := actorID.Int64
			record.ActorUserID = &value
		}
		if actorEmail.Valid {
			record.ActorEmail = actorEmail.String
		}
		if targetID.Valid {
			value := targetID.String
			record.TargetID = &value
		}
		logs = append(logs, record)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, logs)
}
