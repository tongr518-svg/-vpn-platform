package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type API struct {
	db         *pgxpool.Pool
	jwtSecret  []byte
	inviteCode string
}

type accessClaims struct {
	jwt.RegisteredClaims
	TokenVersion int `json:"ver"`
}

type device struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Platform   string     `json:"platform"`
	PublicKey  string     `json:"public_key"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type createDeviceRequest struct {
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	PublicKey string `json:"public_key"`
}

type credentials struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code,omitempty"`
}

type user struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func main() {
	databaseURL := requiredEnv("DATABASE_URL")
	jwtSecret := requiredEnv("JWT_SECRET")
	inviteCode := requiredEnv("INVITE_CODE")
	if len(jwtSecret) < 32 {
		log.Fatal("JWT_SECRET 至少需要 32 个字符")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatal("创建数据库连接池失败：", err)
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		log.Fatal("数据库连接失败：", err)
	}
	if err := applyMigrations(ctx, db); err != nil {
		log.Fatal("数据库迁移失败：", err)
	}

	api := &API{db: db, jwtSecret: []byte(jwtSecret), inviteCode: inviteCode}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("POST /v1/auth/register", api.register)
	mux.HandleFunc("POST /v1/auth/login", api.login)
	mux.HandleFunc("GET /v1/me", api.me)
	mux.HandleFunc("POST /v1/me/password", api.changeMyPassword)
	mux.HandleFunc("GET /v1/devices", api.listDevices)
	mux.HandleFunc("POST /v1/devices", api.createDevice)
	mux.HandleFunc("PATCH /v1/devices/{id}", api.renameMyDevice)
	mux.HandleFunc("DELETE /v1/devices/{id}", api.revokeDevice)
	mux.HandleFunc("GET /v1/me/subscription", api.getMySubscription)
	mux.HandleFunc("GET /v1/admin/users", api.adminListUsers)
	mux.HandleFunc("PATCH /v1/admin/users/{id}/status", api.adminSetUserStatus)
	mux.HandleFunc("GET /v1/admin/plans", api.adminListPlans)
	mux.HandleFunc("POST /v1/admin/plans", api.adminCreatePlan)
	mux.HandleFunc("PATCH /v1/admin/plans/{id}/status", api.adminSetPlanStatus)
	mux.HandleFunc("POST /v1/admin/users/{id}/subscriptions", api.adminCreateSubscription)
	mux.HandleFunc("GET /v1/admin/users/{id}/devices", api.adminListUserDevices)
	mux.HandleFunc("DELETE /v1/admin/users/{id}/devices/{deviceID}", api.adminRevokeUserDevice)
	mux.HandleFunc("GET /v1/admin/subscriptions", api.adminListSubscriptions)
	mux.HandleFunc("POST /v1/admin/subscriptions/{id}/cancel", api.adminCancelSubscription)
	mux.HandleFunc("GET /v1/admin/audit-logs", api.adminListAuditLogs)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
	mux.Handle("GET /admin/", http.StripPrefix("/admin/", adminUIHandler()))

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           apiMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("API listening on %s", addr)
	signalCtx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-signalCtx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	err := server.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}

	stop()
	<-shutdownDone
	log.Println("API server stopped")
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := a.db.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}

	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if address, err := mail.ParseAddress(in.Email); err != nil || address.Address != in.Email {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	if len(in.Password) < 12 || len(in.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password_must_be_12_to_72_bytes"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.InviteCode), []byte(a.inviteCode)) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid_invite_code"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	var u user
	err = a.db.QueryRow(r.Context(),
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 ON CONFLICT (email) DO NOTHING
		 RETURNING id, email, created_at`,
		in.Email, string(hash),
	).Scan(&u.ID, &u.Email, &u.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account_already_exists"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	token, err := a.makeToken(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "token": token})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	var u user
	var hash string
	var status string
	err := a.db.QueryRow(r.Context(),
		`SELECT id, email, password_hash, created_at, status FROM users WHERE email = $1`,
		in.Email,
	).Scan(&u.ID, &u.Email, &hash, &u.CreatedAt, &status)
	if err != nil || status != "active" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}

	token, err := a.makeToken(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "token": token})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	var u user
	err = a.db.QueryRow(r.Context(),
		`SELECT id, email, created_at FROM users WHERE id = $1`,
		userID,
	).Scan(&u.ID, &u.Email, &u.CreatedAt)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (a *API) authenticatedUserID(r *http.Request) (int64, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return 0, jwt.ErrTokenMalformed
	}

	claims := &accessClaims{}
	token, err := jwt.ParseWithClaims(strings.TrimPrefix(header, prefix), claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return a.jwtSecret, nil
		},
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid || claims.Subject == "" {
		return 0, jwt.ErrTokenInvalidClaims
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID < 1 {
		return 0, jwt.ErrTokenInvalidClaims
	}
	var status string
	var tokenVersion int
	err = a.db.QueryRow(r.Context(),
		`SELECT status, token_version FROM users WHERE id = $1`,
		userID,
	).Scan(&status, &tokenVersion)
	if err != nil || status != "active" || claims.TokenVersion != tokenVersion {
		return 0, jwt.ErrTokenInvalidClaims
	}
	return userID, nil
}

func (a *API) createDevice(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var in createDeviceRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_name_must_be_1_to_64_bytes"})
		return
	}
	switch in.Platform {
	case "android", "ios", "windows", "macos":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_platform"})
		return
	}

	// A WireGuard public key decodes to 32 bytes. This only registers the key;
	// it does not connect the device to a VPN tunnel.
	keyBytes, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(keyBytes) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_public_key"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	// Serialize registrations for this user so concurrent requests cannot
	// both pass the active-device count check.
	var userStatus string
	err = tx.QueryRow(r.Context(),
		`SELECT status FROM users WHERE id = $1 FOR UPDATE`,
		userID,
	).Scan(&userStatus)
	if err != nil || userStatus != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "user_not_active"})
		return
	}

	var deviceLimit int64
	err = tx.QueryRow(r.Context(),
		`SELECT p.device_limit
		 FROM subscriptions s
		 JOIN plans p ON p.id = s.plan_id
		 WHERE s.user_id = $1
		   AND s.status = 'active'
		   AND s.starts_at <= NOW()
		   AND s.ends_at > NOW()
		   AND p.active = TRUE
		 ORDER BY s.ends_at DESC
		 LIMIT 1`,
		userID,
	).Scan(&deviceLimit)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "active_subscription_required"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	var activeDeviceCount int64
	err = tx.QueryRow(r.Context(),
		`SELECT COUNT(*)
		 FROM devices
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	).Scan(&activeDeviceCount)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if activeDeviceCount >= deviceLimit {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "device_limit_reached"})
		return
	}

	var d device
	err = tx.QueryRow(r.Context(),
		`INSERT INTO devices (user_id, name, platform, public_key)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (public_key) DO NOTHING
		 RETURNING id, name, platform, public_key, created_at`,
		userID, in.Name, in.Platform, in.PublicKey,
	).Scan(&d.ID, &d.Name, &d.Platform, &d.PublicKey, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "public_key_already_registered"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticatedUserID(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	rows, err := a.db.Query(r.Context(),
		`SELECT id, name, platform, public_key, created_at, last_seen_at, revoked_at
		 FROM devices
		 WHERE user_id = $1
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer rows.Close()

	devices := make([]device, 0)
	for rows.Next() {
		var d device
		if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.PublicKey, &d.CreatedAt, &d.LastSeenAt, &d.RevokedAt); err != nil {
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

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
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

	result, err := a.db.Exec(r.Context(),
		`UPDATE devices
		 SET revoked_at = NOW()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		deviceID, userID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if result.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device_not_found_or_already_revoked"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) makeToken(userID int64) (string, error) {
	now := time.Now()
	var tokenVersion int
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.db.QueryRow(ctx,
		`SELECT token_version FROM users WHERE id = $1`,
		userID,
	).Scan(&tokenVersion); err != nil {
		return "", err
	}

	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   formatID(userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(12 * time.Hour)),
		},
		TokenVersion: tokenVersion,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtSecret)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func requiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s 环境变量不能为空", key)
	}
	return value
}

// formatID converts a positive database ID without pulling in strconv.
func formatID(id int64) string {
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[i:])
}
