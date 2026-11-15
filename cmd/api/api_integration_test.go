package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func testFixture(t *testing.T) (*API, int64, func()) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("设置 TEST_DATABASE_URL 后运行 PostgreSQL 集成测试")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}

	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		adminPool.Close()
		t.Fatalf("生成测试 schema 名称失败: %v", err)
	}
	schemaName := fmt.Sprintf("vpn_test_%x", randomBytes)

	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		adminPool.Close()
		t.Fatalf("创建测试 schema 失败: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE")
		adminPool.Close()
		t.Fatalf("解析数据库配置失败: %v", err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schemaName

	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE")
		adminPool.Close()
		t.Fatalf("创建测试连接池失败: %v", err)
	}

	if err := applyMigrations(ctx, db); err != nil {
		db.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE")
		adminPool.Close()
		t.Fatalf("初始化测试 schema 失败: %v", err)
	}

	api := &API{
		db:         db,
		jwtSecret:  []byte("integration-test-secret-at-least-32-bytes"),
		inviteCode: "test-invite",
	}

	var userID int64
	err = db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ('user@example.test', 'test-hash', 'user', 'active')
		 RETURNING id`,
	).Scan(&userID)
	if err != nil {
		db.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE")
		adminPool.Close()
		t.Fatalf("创建测试用户失败: %v", err)
	}

	cleanup := func() {
		db.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_, _ = adminPool.Exec(dropCtx, "DROP SCHEMA "+schemaName+" CASCADE")
		adminPool.Close()
	}
	return api, userID, cleanup
}

func testRouter(api *API) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/devices", api.listDevices)
	mux.HandleFunc("POST /v1/devices", api.createDevice)
	mux.HandleFunc("PATCH /v1/devices/{id}", api.renameMyDevice)
	mux.HandleFunc("DELETE /v1/devices/{id}", api.revokeDevice)
	mux.HandleFunc("POST /v1/me/password", api.changeMyPassword)
	return mux
}

func testToken(t *testing.T, api *API, userID int64) string {
	t.Helper()
	token, err := api.makeToken(userID)
	if err != nil {
		t.Fatalf("生成测试 JWT 失败: %v", err)
	}
	return token
}

func testRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	token string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()

	var requestBody bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&requestBody).Encode(body); err != nil {
			t.Fatalf("编码测试请求失败: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, &requestBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func addActiveTestPlan(t *testing.T, api *API, userID int64, deviceLimit int) {
	t.Helper()
	ctx := context.Background()

	var planID int64
	err := api.db.QueryRow(ctx,
		`INSERT INTO plans (name, device_limit, concurrent_limit, active)
		 VALUES ('test-plan', $1, 1, TRUE)
		 RETURNING id`,
		deviceLimit,
	).Scan(&planID)
	if err != nil {
		t.Fatalf("创建测试套餐失败: %v", err)
	}

	_, err = api.db.Exec(ctx,
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'active', NOW() - INTERVAL '1 minute', NOW() + INTERVAL '1 day')`,
		userID, planID,
	)
	if err != nil {
		t.Fatalf("创建测试订阅失败: %v", err)
	}
}

func testPublicKey(n byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = n
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestDeviceRegistrationRequiresActiveSubscription(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	response := testRequest(t, testRouter(api), http.MethodPost, "/v1/devices",
		testToken(t, api, userID),
		map[string]any{
			"name":       "test-device",
			"platform":   "windows",
			"public_key": testPublicKey(1),
		},
	)

	if response.Code != http.StatusForbidden {
		t.Fatalf("期望状态码 %d，得到 %d：%s",
			http.StatusForbidden, response.Code, response.Body.String())
	}
}

func TestDeviceRegistrationEnforcesPlanDeviceLimit(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	addActiveTestPlan(t, api, userID, 1)
	handler := testRouter(api)
	token := testToken(t, api, userID)

	first := testRequest(t, handler, http.MethodPost, "/v1/devices", token,
		map[string]any{
			"name":       "first-device",
			"platform":   "windows",
			"public_key": testPublicKey(2),
		},
	)
	if first.Code != http.StatusCreated {
		t.Fatalf("首次注册应成功，得到 %d：%s", first.Code, first.Body.String())
	}

	second := testRequest(t, handler, http.MethodPost, "/v1/devices", token,
		map[string]any{
			"name":       "second-device",
			"platform":   "android",
			"public_key": testPublicKey(3),
		},
	)
	if second.Code != http.StatusConflict {
		t.Fatalf("超出设备上限应返回 %d，得到 %d：%s",
			http.StatusConflict, second.Code, second.Body.String())
	}
}

func TestConcurrentDeviceRegistrationsCannotExceedPlanLimit(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	addActiveTestPlan(t, api, userID, 1)
	handler := testRouter(api)
	token := testToken(t, api, userID)
	start := make(chan struct{})
	statuses := make(chan int, 2)

	for i, key := range []byte{5, 6} {
		go func(index int, keyByte byte) {
			<-start
			response := testRequest(t, handler, http.MethodPost, "/v1/devices", token,
				map[string]any{
					"name":       fmt.Sprintf("parallel-device-%d", index),
					"platform":   "windows",
					"public_key": testPublicKey(keyByte),
				},
			)
			statuses <- response.Code
		}(i, key)
	}
	close(start)

	created, limited := 0, 0
	for range 2 {
		switch <-statuses {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			limited++
		}
	}
	if created != 1 || limited != 1 {
		t.Fatalf("并发注册应各返回一次 %d 和 %d，得到 created=%d conflict=%d",
			http.StatusCreated, http.StatusConflict, created, limited)
	}
}

func TestUserCannotRevokeAnotherUsersDevice(t *testing.T) {
	api, ownerID, cleanup := testFixture(t)
	defer cleanup()

	addActiveTestPlan(t, api, ownerID, 2)
	handler := testRouter(api)

	created := testRequest(t, handler, http.MethodPost, "/v1/devices",
		testToken(t, api, ownerID),
		map[string]any{
			"name":       "owner-device",
			"platform":   "ios",
			"public_key": testPublicKey(4),
		},
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("设备注册失败，得到 %d：%s", created.Code, created.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析设备响应失败: %v", err)
	}
	deviceID, ok := result["id"].(float64)
	if !ok {
		t.Fatalf("设备响应中缺少 ID：%s", created.Body.String())
	}

	var otherUserID int64
	if err := api.db.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ('other@example.test', 'test-hash', 'user', 'active')
		 RETURNING id`,
	).Scan(&otherUserID); err != nil {
		t.Fatalf("创建第二个测试用户失败: %v", err)
	}

	response := testRequest(
		t,
		handler,
		http.MethodDelete,
		fmt.Sprintf("/v1/devices/%d", int64(deviceID)),
		testToken(t, api, otherUserID),
		nil,
	)
	if response.Code != http.StatusNotFound {
		t.Fatalf("跨用户撤销应返回 %d，得到 %d：%s",
			http.StatusNotFound, response.Code, response.Body.String())
	}
}

func TestUserCanRenameOwnDeviceButNotAnotherUsersDevice(t *testing.T) {
	api, ownerID, cleanup := testFixture(t)
	defer cleanup()
	addActiveTestPlan(t, api, ownerID, 2)
	handler := testRouter(api)

	created := testRequest(t, handler, http.MethodPost, "/v1/devices",
		testToken(t, api, ownerID),
		map[string]any{
			"name":       "old-device-name",
			"platform":   "windows",
			"public_key": testPublicKey(21),
		},
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("设备注册失败，得到 %d：%s", created.Code, created.Body.String())
	}

	var createdDevice map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &createdDevice); err != nil {
		t.Fatalf("解析设备响应失败: %v", err)
	}
	deviceID, ok := createdDevice["id"].(float64)
	if !ok {
		t.Fatalf("设备响应中缺少 ID：%s", created.Body.String())
	}

	renamed := testRequest(t, handler, http.MethodPatch,
		fmt.Sprintf("/v1/devices/%d", int64(deviceID)),
		testToken(t, api, ownerID),
		map[string]any{"name": "new-device-name"},
	)
	if renamed.Code != http.StatusOK {
		t.Fatalf("设备所属用户重命名应成功，得到 %d：%s", renamed.Code, renamed.Body.String())
	}
	var renamedDevice map[string]any
	if err := json.Unmarshal(renamed.Body.Bytes(), &renamedDevice); err != nil {
		t.Fatalf("解析重命名响应失败: %v", err)
	}
	if renamedDevice["name"] != "new-device-name" {
		t.Fatalf("响应中的设备名称未更新：%s", renamed.Body.String())
	}

	var otherUserID int64
	if err := api.db.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ('other-rename@example.test', 'test-hash', 'user', 'active')
		 RETURNING id`,
	).Scan(&otherUserID); err != nil {
		t.Fatalf("创建第二个测试用户失败: %v", err)
	}

	forbiddenRename := testRequest(t, handler, http.MethodPatch,
		fmt.Sprintf("/v1/devices/%d", int64(deviceID)),
		testToken(t, api, otherUserID),
		map[string]any{"name": "unauthorized-name"},
	)
	if forbiddenRename.Code != http.StatusNotFound {
		t.Fatalf("跨用户重命名应返回 404，得到 %d：%s",
			http.StatusNotFound, forbiddenRename.Body.String())
	}
}

func TestSuspendedUserCannotLogin(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	password := "test-password-123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("生成测试密码哈希失败: %v", err)
	}

	_, err = api.db.Exec(context.Background(),
		`UPDATE users
		 SET password_hash = $1, status = 'suspended', token_version = token_version + 1
		 WHERE id = $2`,
		string(hash), userID,
	)
	if err != nil {
		t.Fatalf("暂停测试用户失败: %v", err)
	}

	response := testRequest(
		t,
		http.HandlerFunc(api.login),
		http.MethodPost,
		"/v1/auth/login",
		"",
		map[string]any{
			"email":    "user@example.test",
			"password": password,
		},
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("暂停账号登录应返回 401，得到 %d：%s",
			http.StatusUnauthorized, response.Body.String())
	}
}

func TestSuspendedUserCannotUseExistingJWT(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	token := testToken(t, api, userID)
	_, err := api.db.Exec(context.Background(),
		`UPDATE users SET status = 'suspended', token_version = token_version + 1 WHERE id = $1`,
		userID,
	)
	if err != nil {
		t.Fatalf("暂停测试用户失败: %v", err)
	}

	response := testRequest(
		t,
		testRouter(api),
		http.MethodGet,
		"/v1/devices",
		token,
		nil,
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("暂停账号的既有 JWT 应被拒绝，得到 %d：%s",
			http.StatusUnauthorized, response.Code, response.Body.String())
	}

	_, err = api.db.Exec(context.Background(),
		`UPDATE users SET status = 'active' WHERE id = $1`,
		userID,
	)
	if err != nil {
		t.Fatalf("恢复测试用户失败: %v", err)
	}

	response = testRequest(
		t,
		testRouter(api),
		http.MethodGet,
		"/v1/devices",
		token,
		nil,
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("恢复账号后旧 JWT 仍应失效，得到 %d：%s",
			http.StatusUnauthorized, response.Code, response.Body.String())
	}
}

func TestChangePasswordRejectsWrongCurrentPassword(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	const currentPassword = "test-password-123"
	hash, err := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("生成测试密码哈希失败: %v", err)
	}
	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), userID,
	); err != nil {
		t.Fatalf("设置测试密码失败: %v", err)
	}

	response := testRequest(t, testRouter(api), http.MethodPost, "/v1/me/password",
		testToken(t, api, userID),
		map[string]any{
			"current_password": "wrong-current-password",
			"new_password":     "new-test-password-456",
		},
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("错误的当前密码应返回 401，得到 %d：%s",
			http.StatusUnauthorized, response.Body.String())
	}

	login := testRequest(t, http.HandlerFunc(api.login), http.MethodPost, "/v1/auth/login", "",
		map[string]any{"email": "user@example.test", "password": currentPassword},
	)
	if login.Code != http.StatusOK {
		t.Fatalf("错误当前密码不应改变原密码，原密码登录得到 %d：%s",
			login.Code, login.Body.String())
	}
}

func TestChangePasswordInvalidatesOldJWTAndAllowsNewPassword(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	const currentPassword = "test-password-123"
	const newPassword = "new-test-password-456"
	hash, err := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("生成测试密码哈希失败: %v", err)
	}
	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), userID,
	); err != nil {
		t.Fatalf("设置测试密码失败: %v", err)
	}

	oldToken := testToken(t, api, userID)
	changed := testRequest(t, testRouter(api), http.MethodPost, "/v1/me/password", oldToken,
		map[string]any{
			"current_password": currentPassword,
			"new_password":     newPassword,
		},
	)
	if changed.Code != http.StatusNoContent {
		t.Fatalf("修改密码应返回 204，得到 %d：%s", changed.Code, changed.Body.String())
	}

	protected := testRequest(t, testRouter(api), http.MethodGet, "/v1/devices", oldToken, nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("旧 JWT 应失效并返回 401，得到 %d：%s",
			protected.Code, protected.Body.String())
	}

	login := testRequest(t, http.HandlerFunc(api.login), http.MethodPost, "/v1/auth/login", "",
		map[string]any{"email": "user@example.test", "password": newPassword},
	)
	if login.Code != http.StatusOK {
		t.Fatalf("新密码应可登录，得到 %d：%s", login.Code, login.Body.String())
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	api, _, cleanup := testFixture(t)
	defer cleanup()

	ctx := context.Background()
	var before int
	if err := api.db.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&before); err != nil {
		t.Fatalf("查询迁移数量失败: %v", err)
	}

	if err := applyMigrations(ctx, api.db); err != nil {
		t.Fatalf("重复执行迁移应成功: %v", err)
	}

	var after int
	if err := api.db.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&after); err != nil {
		t.Fatalf("再次查询迁移数量失败: %v", err)
	}
	if after != before {
		t.Fatalf("重复执行迁移不应新增版本记录：之前 %d 条，现在 %d 条", before, after)
	}
}

func TestMigrationChecksumMismatchStopsMigration(t *testing.T) {
	api, _, cleanup := testFixture(t)
	defer cleanup()

	ctx := context.Background()
	var version string
	if err := api.db.QueryRow(ctx,
		`SELECT version FROM schema_migrations ORDER BY version LIMIT 1`,
	).Scan(&version); err != nil {
		t.Fatalf("查询迁移版本失败: %v", err)
	}

	if _, err := api.db.Exec(ctx,
		`UPDATE schema_migration_checksums
		 SET checksum = 'intentionally-tampered'
		 WHERE version = $1`,
		version,
	); err != nil {
		t.Fatalf("修改测试校验和失败: %v", err)
	}

	if err := applyMigrations(ctx, api.db); err == nil {
		t.Fatal("迁移校验和不匹配时应返回错误")
	}
}

func TestAdminAPIRequiresAdminRole(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/admin/users", api.adminListUsers)
	mux.HandleFunc("POST /v1/admin/plans", api.adminCreatePlan)

	handler := apiMiddleware(mux)
	token := testToken(t, api, userID)

	response := testRequest(t, handler, http.MethodGet, "/v1/admin/users", "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("未登录访问管理员接口应返回 401，得到 %d：%s",
			http.StatusUnauthorized, response.Code, response.Body.String())
	}

	response = testRequest(t, handler, http.MethodGet, "/v1/admin/users", token, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("普通用户访问管理员接口应返回 403，得到 %d：%s",
			http.StatusForbidden, response.Code, response.Body.String())
	}

	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET role = 'admin' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}

	response = testRequest(t, handler, http.MethodPost, "/v1/admin/plans", token,
		map[string]any{
			"name":              "integration-plan",
			"device_limit":      2,
			"concurrent_limit":  1,
			"data_limit_bytes":  0,
			"speed_limit_mbps":  0,
		},
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("管理员创建套餐应返回 201，得到 %d：%s",
			http.StatusCreated, response.Code, response.Body.String())
	}

	var auditCount int
	if err := api.db.QueryRow(context.Background(),
		`SELECT COUNT(*)
		 FROM admin_audit_logs
		 WHERE actor_user_id = $1
		   AND action = 'create_plan'`,
		userID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询套餐创建审计记录失败: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("创建套餐后应有 1 条审计记录，实际为 %d", auditCount)
	}
}

func TestAdminCannotCancelExpiredSubscription(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	ctx := context.Background()
	if _, err := api.db.Exec(ctx,
		`UPDATE users SET role = 'admin' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}

	var planID, subscriptionID int64
	err := api.db.QueryRow(ctx,
		`INSERT INTO plans (name, device_limit, concurrent_limit, active)
		 VALUES ('expired-test-plan', 1, 1, TRUE)
		 RETURNING id`,
	).Scan(&planID)
	if err != nil {
		t.Fatalf("创建测试套餐失败: %v", err)
	}

	err = api.db.QueryRow(ctx,
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'active', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day')
		 RETURNING id`,
		userID, planID,
	).Scan(&subscriptionID)
	if err != nil {
		t.Fatalf("创建过期测试订阅失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(
		"POST /v1/admin/subscriptions/{id}/cancel",
		api.adminCancelSubscription,
	)
	response := testRequest(
		t,
		mux,
		http.MethodPost,
		fmt.Sprintf("/v1/admin/subscriptions/%d/cancel", subscriptionID),
		testToken(t, api, userID),
		nil,
	)
	if response.Code != http.StatusConflict {
		t.Fatalf("取消过期订阅应返回 409，得到 %d：%s",
			http.StatusConflict, response.Body.String())
	}

	var status string
	err = api.db.QueryRow(ctx,
		`SELECT status FROM subscriptions WHERE id = $1`,
		subscriptionID,
	).Scan(&status)
	if err != nil {
		t.Fatalf("查询订阅状态失败: %v", err)
	}
	if status != "active" {
		t.Fatalf("过期订阅状态不应被取消接口修改，实际为 %q", status)
	}
}
