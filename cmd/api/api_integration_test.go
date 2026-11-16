package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func testFixture(t *testing.T) (*API, int64, func()) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("REQUIRE_INTEGRATION_TESTS") == "1" {
			t.Fatal("CI 要求运行集成测试，但 TEST_DATABASE_URL 未设置")
		}
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
	return newRouter(api)
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

func testAdminToken(t *testing.T, api *API, userID int64) string {
	t.Helper()
	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET role = 'admin' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	return testToken(t, api, userID)
}

func createTestInvite(t *testing.T, handler http.Handler, token string, maxUses int) (int64, string) {
	t.Helper()
	response := testRequest(t, handler, http.MethodPost, "/v1/admin/invites", token,
		map[string]any{"max_uses": maxUses})
	if response.Code != http.StatusCreated {
		t.Fatalf("创建测试邀请码失败，得到 %d：%s", response.Code, response.Body.String())
	}
	var result struct {
		Code   string `json:"code"`
		Invite struct {
			ID int64 `json:"id"`
		} `json:"invite"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析邀请码创建响应失败: %v", err)
	}
	if result.Code == "" || result.Invite.ID <= 0 {
		t.Fatalf("邀请码创建响应缺少原码或 ID：%s", response.Body.String())
	}
	return result.Invite.ID, result.Code
}

func registerWithInvite(t *testing.T, handler http.Handler, email, inviteCode string) *httptest.ResponseRecorder {
	t.Helper()
	return testRequest(t, handler, http.MethodPost, "/v1/auth/register", "",
		map[string]any{
			"email":       email,
			"password":    "test-password-123",
			"invite_code": inviteCode,
		})
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

func TestExistingSubscriptionWorksAfterPlanIsDeactivated(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	addActiveTestPlan(t, api, userID, 1)

	ctx := context.Background()
	var planID int64
	if err := api.db.QueryRow(ctx,
		`SELECT plan_id FROM subscriptions WHERE user_id = $1 ORDER BY id DESC LIMIT 1`,
		userID,
	).Scan(&planID); err != nil {
		t.Fatalf("查询测试套餐失败: %v", err)
	}

	if _, err := api.db.Exec(ctx,
		`UPDATE plans SET active = FALSE WHERE id = $1`,
		planID,
	); err != nil {
		t.Fatalf("停用测试套餐失败: %v", err)
	}

	response := testRequest(
		t,
		testRouter(api),
		http.MethodPost,
		"/v1/devices",
		testToken(t, api, userID),
		map[string]any{
			"name":       "existing-subscriber-device",
			"platform":   "windows",
			"public_key": testPublicKey(9),
		},
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("已有有效订阅的用户仍应可注册设备，得到 %d：%s",
			response.Code, response.Body.String())
	}
}

func TestListMySubscriptionsShowsHistoryAndOnlyOwnRecords(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()

	var planID int64
	if err := api.db.QueryRow(ctx,
		`INSERT INTO plans (name, device_limit, concurrent_limit)
		 VALUES ('history-plan', 2, 1)
		 RETURNING id`,
	).Scan(&planID); err != nil {
		t.Fatalf("创建测试套餐失败: %v", err)
	}

	_, err := api.db.Exec(ctx,
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'active', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
		        ($1, $2, 'cancelled', NOW() - INTERVAL '1 hour', NOW() + INTERVAL '1 day')`,
		userID, planID,
	)
	if err != nil {
		t.Fatalf("创建测试用户订阅历史失败: %v", err)
	}
	var explicitlyExpiredID int64
	if err := api.db.QueryRow(ctx,
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'expired', NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day')
		 RETURNING id`,
		userID, planID,
	).Scan(&explicitlyExpiredID); err != nil {
		t.Fatalf("创建状态与日期不一致的订阅失败: %v", err)
	}

	var otherUserID int64
	if err := api.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ('history-other@example.test', 'test-hash', 'user', 'active')
		 RETURNING id`,
	).Scan(&otherUserID); err != nil {
		t.Fatalf("创建另一测试用户失败: %v", err)
	}
	if _, err := api.db.Exec(ctx,
		`INSERT INTO subscriptions (user_id, plan_id, status, starts_at, ends_at)
		 VALUES ($1, $2, 'active', NOW() - INTERVAL '1 minute', NOW() + INTERVAL '1 day')`,
		otherUserID, planID,
	); err != nil {
		t.Fatalf("创建另一用户订阅失败: %v", err)
	}

	response := testRequest(t, testRouter(api), http.MethodGet,
		"/v1/me/subscriptions", testToken(t, api, userID), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("订阅历史查询应返回 200，得到 %d：%s", response.Code, response.Body.String())
	}
	var subscriptions []userSubscriptionRecord
	if err := json.Unmarshal(response.Body.Bytes(), &subscriptions); err != nil {
		t.Fatalf("解析订阅历史失败: %v", err)
	}
	if len(subscriptions) != 3 {
		t.Fatalf("只应返回当前用户的 3 条订阅，实际为 %d：%s", len(subscriptions), response.Body.String())
	}
	statuses := make(map[string]bool, len(subscriptions))
	statusByID := make(map[int64]string, len(subscriptions))
	for _, subscription := range subscriptions {
		if subscription.PlanName != "history-plan" {
			t.Errorf("套餐名称不匹配：%q", subscription.PlanName)
		}
		statuses[subscription.Status] = true
		statusByID[subscription.ID] = subscription.Status
	}
	if !statuses["expired"] || !statuses["cancelled"] {
		t.Fatalf("应返回 expired 和 cancelled 展示状态，实际为 %#v", statuses)
	}
	if statusByID[explicitlyExpiredID] != "expired" {
		t.Fatalf("数据库状态为 expired 的记录应继续显示 expired，即使结束时间在未来；实际状态为 %q", statusByID[explicitlyExpiredID])
	}
}

func TestListMySubscriptionsReturnsEmptyArrayWithoutHistory(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()

	response := testRequest(t, testRouter(api), http.MethodGet,
		"/v1/me/subscriptions", testToken(t, api, userID), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("无订阅历史时应返回 200，得到 %d：%s", response.Code, response.Body.String())
	}
	var subscriptions []userSubscriptionRecord
	if err := json.Unmarshal(response.Body.Bytes(), &subscriptions); err != nil {
		t.Fatalf("解析空订阅历史失败: %v", err)
	}
	if subscriptions == nil || len(subscriptions) != 0 {
		t.Fatalf("无订阅历史时应返回空数组，得到 %s", response.Body.String())
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
	var auditCountBefore int
	if err := api.db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_logs`,
	).Scan(&auditCountBefore); err != nil {
		t.Fatalf("查询撤销前审计记录数量失败: %v", err)
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
	var auditCountAfter int
	if err := api.db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_logs`,
	).Scan(&auditCountAfter); err != nil {
		t.Fatalf("查询撤销后审计记录数量失败: %v", err)
	}
	if auditCountAfter != auditCountBefore {
		t.Fatalf("跨用户撤销不应新增审计记录：之前 %d 条，现在 %d 条", auditCountBefore, auditCountAfter)
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

func TestDeviceLifecycleWritesAuditAndRejectedCrossUserActionDoesNot(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	addActiveTestPlan(t, api, userID, 1)

	ctx := context.Background()
	handler := testRouter(api)
	token := testToken(t, api, userID)

	created := testRequest(t, handler, http.MethodPost, "/v1/devices", token,
		map[string]any{
			"name":       "audit-device",
			"platform":   "windows",
			"public_key": testPublicKey(31),
		},
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("设备注册失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var createdDevice map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &createdDevice); err != nil {
		t.Fatalf("解析注册响应失败: %v", err)
	}
	deviceID, ok := createdDevice["id"].(float64)
	if !ok {
		t.Fatalf("注册响应中缺少设备 ID：%s", created.Body.String())
	}
	assertDeviceAudit := func(action string) {
		t.Helper()
		var count int
		if err := api.db.QueryRow(ctx,
			`SELECT COUNT(*) FROM admin_audit_logs
			 WHERE actor_user_id = $1 AND action = $2
			   AND target_type = 'device' AND target_id = $3`,
			userID, action, fmt.Sprint(int64(deviceID)),
		).Scan(&count); err != nil {
			t.Fatalf("查询 %s 审计记录失败: %v", action, err)
		}
		if count != 1 {
			t.Fatalf("%s 应有 1 条设备审计记录，实际为 %d", action, count)
		}
	}
	assertDeviceAudit("register_device")

	renamePath := fmt.Sprintf("/v1/devices/%d", int64(deviceID))
	renamed := testRequest(t, handler, http.MethodPatch, renamePath, token,
		map[string]any{"name": "renamed-audit-device"})
	if renamed.Code != http.StatusOK {
		t.Fatalf("设备重命名失败，得到 %d：%s", renamed.Code, renamed.Body.String())
	}
	assertDeviceAudit("rename_device")

	var otherUserID int64
	if err := api.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ('audit-other@example.test', 'test-hash', 'user', 'active')
		 RETURNING id`,
	).Scan(&otherUserID); err != nil {
		t.Fatalf("创建第二个测试用户失败: %v", err)
	}
	var auditCountBefore int
	if err := api.db.QueryRow(ctx, `SELECT COUNT(*) FROM admin_audit_logs`).Scan(&auditCountBefore); err != nil {
		t.Fatalf("查询审计记录数量失败: %v", err)
	}
	denied := testRequest(t, handler, http.MethodPatch, renamePath,
		testToken(t, api, otherUserID), map[string]any{"name": "forbidden-name"})
	if denied.Code != http.StatusNotFound {
		t.Fatalf("跨用户重命名应返回 404，得到 %d：%s", denied.Code, denied.Body.String())
	}
	var auditCountAfter int
	if err := api.db.QueryRow(ctx, `SELECT COUNT(*) FROM admin_audit_logs`).Scan(&auditCountAfter); err != nil {
		t.Fatalf("再次查询审计记录数量失败: %v", err)
	}
	if auditCountAfter != auditCountBefore {
		t.Fatalf("跨用户操作不应新增审计记录：之前 %d 条，现在 %d 条", auditCountBefore, auditCountAfter)
	}

	revoked := testRequest(t, handler, http.MethodDelete, renamePath, token, nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("设备撤销失败，得到 %d：%s", revoked.Code, revoked.Body.String())
	}
	assertDeviceAudit("revoke_device")
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

func TestRevokeMySessionsInvalidatesCurrentJWTAndAudits(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	token := testToken(t, api, userID)
	handler := testRouter(api)

	revoked := testRequest(t, handler, http.MethodPost,
		"/v1/me/sessions/revoke", token, nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("撤销会话应返回 204，得到 %d：%s", revoked.Code, revoked.Body.String())
	}

	protected := testRequest(t, handler, http.MethodGet, "/v1/me", token, nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("撤销后原 JWT 应返回 401，得到 %d：%s", protected.Code, protected.Body.String())
	}

	var auditCount int
	if err := api.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_logs
		 WHERE actor_user_id = $1 AND action = 'revoke_sessions'
		   AND target_type = 'user' AND target_id = $2`,
		userID, fmt.Sprint(userID),
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询会话撤销审计记录失败: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("撤销会话后应有 1 条审计记录，实际为 %d", auditCount)
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
		t.Fatalf("暂停账号的既有 JWT 应被拒绝，期望 %d，得到 %d：%s",
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
		t.Fatalf("恢复账号后旧 JWT 仍应失效，期望 %d，得到 %d：%s",
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
		t.Fatalf("未登录访问管理员接口应返回 401，实际得到 %d：%s",
			response.Code, response.Body.String())
	}

	response = testRequest(t, handler, http.MethodGet, "/v1/admin/users", token, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("普通用户访问管理员接口应返回 403，实际得到 %d：%s",
			response.Code, response.Body.String())
	}

	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET role = 'admin' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}

	response = testRequest(t, handler, http.MethodPost, "/v1/admin/plans", token,
		map[string]any{
			"name":             "integration-plan",
			"device_limit":     2,
			"concurrent_limit": 1,
			"data_limit_bytes": 0,
			"speed_limit_mbps": 0,
		},
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("管理员创建套餐应返回 201，实际得到 %d：%s",
			response.Code, response.Body.String())
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

func TestInviteRegistrationConsumesUseAndStoresOnlyHash(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	adminToken := testAdminToken(t, api, adminID)
	handler := testRouter(api)

	inviteID, code := createTestInvite(t, handler, adminToken, 1)
	var storedHash []byte
	if err := api.db.QueryRow(context.Background(),
		`SELECT code_hash FROM invite_codes WHERE id = $1`, inviteID,
	).Scan(&storedHash); err != nil {
		t.Fatalf("读取邀请码哈希失败: %v", err)
	}
	expectedHash := sha256.Sum256([]byte(code))
	if !bytes.Equal(storedHash, expectedHash[:]) {
		t.Fatal("数据库中存储的邀请码不是原码的 SHA-256 哈希")
	}

	listResponse := testRequest(t, handler, http.MethodGet, "/v1/admin/invites", adminToken, nil)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("查询邀请码应返回 200，得到 %d：%s", listResponse.Code, listResponse.Body.String())
	}
	if strings.Contains(listResponse.Body.String(), code) || strings.Contains(listResponse.Body.String(), "code_hash") {
		t.Fatalf("邀请码列表不应包含原码或哈希字段：%s", listResponse.Body.String())
	}

	registered := registerWithInvite(t, handler, "invite-success@example.test", code)
	if registered.Code != http.StatusCreated {
		t.Fatalf("有效邀请码注册应成功，得到 %d：%s", registered.Code, registered.Body.String())
	}
	var uses int
	if err := api.db.QueryRow(context.Background(),
		`SELECT uses FROM invite_codes WHERE id = $1`, inviteID,
	).Scan(&uses); err != nil {
		t.Fatalf("读取邀请码使用次数失败: %v", err)
	}
	if uses != 1 {
		t.Fatalf("邀请码使用次数应为 1，实际为 %d", uses)
	}

	reused := registerWithInvite(t, handler, "invite-reuse@example.test", code)
	if reused.Code != http.StatusForbidden {
		t.Fatalf("达到次数上限的邀请码应返回 403，得到 %d：%s", reused.Code, reused.Body.String())
	}

	auditResponse := testRequest(t, handler, http.MethodGet, "/v1/admin/audit-logs", adminToken, nil)
	if auditResponse.Code != http.StatusOK {
		t.Fatalf("查询审计记录应返回 200，得到 %d：%s", auditResponse.Code, auditResponse.Body.String())
	}
	if strings.Contains(auditResponse.Body.String(), code) {
		t.Fatal("审计记录中不应包含邀请码原码")
	}
}

func TestExpiredAndRevokedInviteCodesCannotRegister(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	adminToken := testAdminToken(t, api, adminID)
	handler := testRouter(api)

	expiredID, expiredCode := createTestInvite(t, handler, adminToken, 2)
	if _, err := api.db.Exec(context.Background(),
		`UPDATE invite_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`,
		expiredID,
	); err != nil {
		t.Fatalf("设置邀请码过期失败: %v", err)
	}
	expired := registerWithInvite(t, handler, "expired-invite@example.test", expiredCode)
	if expired.Code != http.StatusForbidden {
		t.Fatalf("过期邀请码应返回 403，得到 %d：%s", expired.Code, expired.Body.String())
	}

	revokedID, revokedCode := createTestInvite(t, handler, adminToken, 2)
	revoked := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/invites/%d", revokedID), adminToken, nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("撤销邀请码应返回 204，得到 %d：%s", revoked.Code, revoked.Body.String())
	}
	registration := registerWithInvite(t, handler, "revoked-invite@example.test", revokedCode)
	if registration.Code != http.StatusForbidden {
		t.Fatalf("已撤销邀请码应返回 403，得到 %d：%s", registration.Code, registration.Body.String())
	}
}

func TestInviteEmailConflictDoesNotConsumeUse(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	adminToken := testAdminToken(t, api, adminID)
	handler := testRouter(api)
	inviteID, code := createTestInvite(t, handler, adminToken, 1)

	conflict := registerWithInvite(t, handler, "user@example.test", code)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("重复邮箱注册应返回 409，得到 %d：%s", conflict.Code, conflict.Body.String())
	}
	var uses int
	if err := api.db.QueryRow(context.Background(),
		`SELECT uses FROM invite_codes WHERE id = $1`, inviteID,
	).Scan(&uses); err != nil {
		t.Fatalf("查询冲突后的使用次数失败: %v", err)
	}
	if uses != 0 {
		t.Fatalf("邮箱冲突不应消耗邀请码，实际 uses=%d", uses)
	}

	registered := registerWithInvite(t, handler, "after-conflict@example.test", code)
	if registered.Code != http.StatusCreated {
		t.Fatalf("冲突未消耗次数，后续有效注册应成功，得到 %d：%s", registered.Code, registered.Body.String())
	}
}

func TestConcurrentInviteRegistrationsRespectUseLimit(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	adminToken := testAdminToken(t, api, adminID)
	_, code := createTestInvite(t, testRouter(api), adminToken, 3)
	handler := http.HandlerFunc(api.register)

	const requests = 10
	responses := make([]int, requests)
	var wg sync.WaitGroup
	wg.Add(requests)
	for i := range requests {
		go func(i int) {
			defer wg.Done()
			response := registerWithInvite(t, handler,
				fmt.Sprintf("parallel-%d@example.test", i), code)
			responses[i] = response.Code
		}(i)
	}
	wg.Wait()

	created, rejected := 0, 0
	for _, status := range responses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
			rejected++
		default:
			t.Fatalf("并发注册得到意外状态码 %d", status)
		}
	}
	if created != 3 || rejected != requests-3 {
		t.Fatalf("邀请码最多应成功使用 3 次；成功 %d 次，拒绝 %d 次", created, rejected)
	}
}

func TestNonAdminCannotCreateOrRevokeInvites(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	handler := testRouter(api)
	token := testToken(t, api, userID)

	createDenied := testRequest(t, handler, http.MethodPost, "/v1/admin/invites", token,
		map[string]any{"max_uses": 1})
	if createDenied.Code != http.StatusForbidden {
		t.Fatalf("普通用户创建邀请码应返回 403，得到 %d：%s", createDenied.Code, createDenied.Body.String())
	}

	adminToken := testAdminToken(t, api, userID)
	inviteID, _ := createTestInvite(t, handler, adminToken, 1)
	if _, err := api.db.Exec(context.Background(),
		`UPDATE users SET role = 'user' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("将测试账号降为普通用户失败: %v", err)
	}
	revokeDenied := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/invites/%d", inviteID), adminToken, nil)
	if revokeDenied.Code != http.StatusForbidden {
		t.Fatalf("普通用户撤销邀请码应返回 403，得到 %d：%s", revokeDenied.Code, revokeDenied.Body.String())
	}
	var isRevoked bool
	if err := api.db.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM invite_codes WHERE id = $1`, inviteID,
	).Scan(&isRevoked); err != nil {
		t.Fatalf("检查邀请码撤销状态失败: %v", err)
	}
	if isRevoked {
		t.Fatal("普通用户请求不应撤销邀请码")
	}
}

func TestLegacyInviteOnlyWorksBeforeFirstAdmin(t *testing.T) {
	t.Run("before admin exists", func(t *testing.T) {
		api, _, cleanup := testFixture(t)
		defer cleanup()
		response := registerWithInvite(t, http.HandlerFunc(api.register),
			"legacy-before-admin@example.test", "test-invite")
		if response.Code != http.StatusCreated {
			t.Fatalf("尚无管理员时旧邀请码应兼容注册，得到 %d：%s", response.Code, response.Body.String())
		}
	})

	t.Run("after admin exists", func(t *testing.T) {
		api, adminID, cleanup := testFixture(t)
		defer cleanup()
		testAdminToken(t, api, adminID)
		response := registerWithInvite(t, http.HandlerFunc(api.register),
			"legacy-after-admin@example.test", "test-invite")
		if response.Code != http.StatusForbidden {
			t.Fatalf("已有管理员后旧邀请码应失效，得到 %d：%s", response.Code, response.Body.String())
		}
	})
}
