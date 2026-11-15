package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type adminUser struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type planRecord struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	DeviceLimit     int       `json:"device_limit"`
	ConcurrentLimit int       `json:"concurrent_limit"`
	DataLimitBytes  int64     `json:"data_limit_bytes"`
	SpeedLimitMbps  int       `json:"speed_limit_mbps"`
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"created_at"`
}

type createPlanRequest struct {
	Name            string `json:"name"`
	DeviceLimit     int    `json:"device_limit"`
	ConcurrentLimit int    `json:"concurrent_limit"`
	DataLimitBytes  int64  `json:"data_limit_bytes"`
	SpeedLimitMbps  int    `json:"speed_limit_mbps"`
}

type setStatusRequest struct {
	Status string `json:"status"`
}

type setActiveRequest struct {
	Active bool `json:"active"`
}

type createSubscriptionRequest struct {
	PlanID   int64     `json:"plan_id"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

type mySubscription struct {
	ID              int64     `json:"id"`
	PlanID          int64     `json:"plan_id"`
	PlanName        string    `json:"plan_name"`
	DeviceLimit     int       `json:"device_limit"`
	ConcurrentLimit int       `json:"concurrent_limit"`
	DataLimitBytes  int64     `json:"data_limit_bytes"`
	SpeedLimitMbps  int       `json:"speed_limit_mbps"`
	StartsAt        time.Time `json:"starts_at"`
	EndsAt          time.Time `json:"ends_at"`
}

// requireAdmin reads the role and status from PostgreSQL, never from client claims.
func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return 0, false
	}

	var role, status string
	err = a.db.QueryRow(r.Context(), `SELECT role, status FROM users WHERE id = $1`, userID).Scan(&role, &status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && status != "active") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return 0, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return 0, false
	}
	if role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin_required"})
		return 0, false
	}
	return userID, true
}

func (a *API) adminListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	rows, err := a.db.Query(r.Context(),
		`SELECT id, email, role, status, created_at
		 FROM users ORDER BY id DESC LIMIT 500`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	users := make([]adminUser, 0)
	for rows.Next() {
		var u adminUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Status, &u.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *API) adminSetUserStatus(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	targetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || targetID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}
	if targetID == actorID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot_change_own_status"})
		return
	}
	var in setStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Status != "active" && in.Status != "suspended" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(),
		`UPDATE users
		 SET status = $1, token_version = token_version + 1
		 WHERE id = $2`,
		in.Status, targetID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if result.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	if err := insertAudit(r, tx, actorID, "set_user_status", "user", targetID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) adminListPlans(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	rows, err := a.db.Query(r.Context(),
		`SELECT id, name, device_limit, concurrent_limit,
		        COALESCE(data_limit_bytes, 0), COALESCE(speed_limit_mbps, 0), active, created_at
		 FROM plans ORDER BY id`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	plans := make([]planRecord, 0)
	for rows.Next() {
		var p planRecord
		if err := rows.Scan(&p.ID, &p.Name, &p.DeviceLimit, &p.ConcurrentLimit, &p.DataLimitBytes, &p.SpeedLimitMbps, &p.Active, &p.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		plans = append(plans, p)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, plans)
}

func (a *API) adminCreatePlan(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	var in createPlanRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 80 || in.DeviceLimit < 1 || in.DeviceLimit > 100 ||
		in.ConcurrentLimit < 1 || in.ConcurrentLimit > in.DeviceLimit || in.DataLimitBytes < 0 || in.SpeedLimitMbps < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_plan"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	var p planRecord
	err = tx.QueryRow(r.Context(),
		`INSERT INTO plans (name, device_limit, concurrent_limit, data_limit_bytes, speed_limit_mbps)
		 VALUES ($1, $2, $3, NULLIF($4, 0), NULLIF($5, 0))
		 RETURNING id, name, device_limit, concurrent_limit,
		           COALESCE(data_limit_bytes, 0), COALESCE(speed_limit_mbps, 0), active, created_at`,
		in.Name, in.DeviceLimit, in.ConcurrentLimit, in.DataLimitBytes, in.SpeedLimitMbps,
	).Scan(&p.ID, &p.Name, &p.DeviceLimit, &p.ConcurrentLimit, &p.DataLimitBytes, &p.SpeedLimitMbps, &p.Active, &p.CreatedAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "create_plan", "plan", p.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (a *API) adminSetPlanStatus(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	planID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || planID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_plan_id"})
		return
	}
	var in setActiveRequest
	if !decodeJSON(w, r, &in) {
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE plans SET active = $1 WHERE id = $2`, in.Active, planID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if result.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plan_not_found"})
		return
	}
	if err := insertAudit(r, tx, actorID, "set_plan_status", "plan", planID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) adminCreateSubscription(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || userID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}
	var in createSubscriptionRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	now := time.Now()
	if in.PlanID <= 0 || in.StartsAt.IsZero() || in.EndsAt.IsZero() || !in.EndsAt.After(in.StartsAt) || in.EndsAt.After(now.AddDate(10, 0, 0)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_subscription"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	var userStatus string
	err = tx.QueryRow(r.Context(), `SELECT status FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&userStatus)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && userStatus != "active") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "active_user_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	var planActive bool
	err = tx.QueryRow(r.Context(), `SELECT active FROM plans WHERE id = $1`, in.PlanID).Scan(&planActive)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !planActive) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "active_plan_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	var overlaps bool
	err = tx.QueryRow(r.Context(),
		`SELECT EXISTS (
		   SELECT 1 FROM subscriptions
		   WHERE user_id = $1 AND status = 'active' AND starts_at < $3 AND ends_at > $2
		 )`, userID, in.StartsAt, in.EndsAt,
	).Scan(&overlaps)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if overlaps {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription_period_overlaps"})
		return
	}

	var subscriptionID int64
	err = tx.QueryRow(r.Context(),
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'active', $3, $4) RETURNING id`,
		userID, in.PlanID, in.StartsAt, in.EndsAt,
	).Scan(&subscriptionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "create_subscription", "subscription", subscriptionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": subscriptionID, "user_id": userID, "plan_id": in.PlanID,
		"status": "active", "starts_at": in.StartsAt, "ends_at": in.EndsAt,
	})
}

func (a *API) getMySubscription(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var s mySubscription
	err = a.db.QueryRow(r.Context(),
		`SELECT s.id, p.id, p.name, p.device_limit, p.concurrent_limit,
		        COALESCE(p.data_limit_bytes, 0), COALESCE(p.speed_limit_mbps, 0), s.starts_at, s.ends_at
		 FROM subscriptions s JOIN plans p ON p.id = s.plan_id
		 WHERE s.user_id = $1 AND s.status = 'active'
		   AND s.starts_at <= NOW() AND s.ends_at > NOW()
		 ORDER BY s.ends_at DESC LIMIT 1`, userID,
	).Scan(&s.ID, &s.PlanID, &s.PlanName, &s.DeviceLimit, &s.ConcurrentLimit,
		&s.DataLimitBytes, &s.SpeedLimitMbps, &s.StartsAt, &s.EndsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no_active_subscription"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func insertAudit(r *http.Request, tx pgx.Tx, actorID int64, action, targetType string, targetID int64) error {
	_, err := tx.Exec(r.Context(),
		`INSERT INTO admin_audit_logs (actor_user_id, action, target_type, target_id)
		 VALUES ($1, $2, $3, $4)`,
		actorID, action, targetType, strconv.FormatInt(targetID, 10),
	)
	return err
}
