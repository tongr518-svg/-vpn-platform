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

func addTestDevice(t *testing.T, api *API, userID int64, name string, keyByte byte) int64 {
	t.Helper()
	var deviceID int64
	err := api.db.QueryRow(context.Background(),
		`INSERT INTO devices (user_id, name, platform, public_key)
		 VALUES ($1, $2, 'windows', $3)
		 RETURNING id`,
		userID, name, testPublicKey(keyByte),
	).Scan(&deviceID)
	if err != nil {
		t.Fatalf("创建测试设备失败: %v", err)
	}
	return deviceID
}

func addTestUser(t *testing.T, api *API, email string, status string) int64 {
	t.Helper()
	var userID int64
	err := api.db.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, role, status)
		 VALUES ($1, 'test-hash', 'user', $2) RETURNING id`,
		email, status,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	return userID
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

func TestNodeAdministrationAndCredentialLifecycle(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	handler := testRouter(api)
	userToken := testToken(t, api, userID)

	denied := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", userToken,
		map[string]any{"name": "edge-a", "region": "test", "capacity": 100, "tunnel_cidr": "10.77.0.0/16"})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("普通用户创建节点应返回 403，得到 %d：%s", denied.Code, denied.Body.String())
	}

	if _, err := api.db.Exec(context.Background(), `UPDATE users SET role = 'admin' WHERE id = $1`, userID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	adminToken := testToken(t, api, userID)
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "edge-a", "region": "test-region", "capacity": 100, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("管理员创建节点应返回 201，得到 %d：%s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatalf("解析节点创建响应失败: %v", err)
	}
	if createdBody.Node.ID <= 0 || createdBody.Credential == "" {
		t.Fatalf("节点响应缺少 ID 或一次性凭据: %s", created.Body.String())
	}
	nodeID := createdBody.Node.ID
	firstCredential := createdBody.Credential

	var storedHash []byte
	if err := api.db.QueryRow(context.Background(), `SELECT token_hash FROM node_credentials WHERE node_id = $1`, nodeID).Scan(&storedHash); err != nil {
		t.Fatalf("查询节点凭据哈希失败: %v", err)
	}
	expectedHash := sha256.Sum256([]byte(firstCredential))
	if !bytes.Equal(storedHash, expectedHash[:]) {
		t.Fatal("数据库未保存节点凭据的 SHA-256 哈希")
	}
	if bytes.Contains(storedHash, []byte(firstCredential)) {
		t.Fatal("数据库不应保存节点明文凭据")
	}

	heartbeat := func(credential string) *httptest.ResponseRecorder {
		return testRequest(t, handler, http.MethodPost, "/v1/node/heartbeat", credential, nil)
	}
	if response := heartbeat(firstCredential); response.Code != http.StatusNoContent {
		t.Fatalf("有效节点凭据心跳应返回 204，得到 %d：%s", response.Code, response.Body.String())
	}

	maintenance := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d/status", nodeID), adminToken,
		map[string]string{"status": "maintenance"})
	if maintenance.Code != http.StatusOK {
		t.Fatalf("节点进入维护状态应返回 200，得到 %d：%s", maintenance.Code, maintenance.Body.String())
	}
	if response := heartbeat(firstCredential); response.Code != http.StatusNoContent {
		t.Fatalf("维护状态仍应接受健康心跳，得到 %d：%s", response.Code, response.Body.String())
	}

	rotated := testRequest(t, handler, http.MethodPost,
		fmt.Sprintf("/v1/admin/nodes/%d/credentials/rotate", nodeID), adminToken, nil)
	if rotated.Code != http.StatusCreated {
		t.Fatalf("凭据轮换应返回 201，得到 %d：%s", rotated.Code, rotated.Body.String())
	}
	var rotatedBody map[string]string
	if err := json.Unmarshal(rotated.Body.Bytes(), &rotatedBody); err != nil {
		t.Fatalf("解析轮换响应失败: %v", err)
	}
	newCredential := rotatedBody["credential"]
	if newCredential == "" || newCredential == firstCredential {
		t.Fatal("轮换后应返回新的凭据")
	}
	if response := heartbeat(firstCredential); response.Code != http.StatusUnauthorized {
		t.Fatalf("旧凭据轮换后应返回 401，得到 %d", response.Code)
	}
	if response := heartbeat(newCredential); response.Code != http.StatusNoContent {
		t.Fatalf("新凭据心跳应返回 204，得到 %d：%s", response.Code, response.Body.String())
	}

	disabled := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d/status", nodeID), adminToken,
		map[string]string{"status": "disabled"})
	if disabled.Code != http.StatusOK {
		t.Fatalf("停用节点应返回 200，得到 %d：%s", disabled.Code, disabled.Body.String())
	}
	if response := heartbeat(newCredential); response.Code != http.StatusUnauthorized {
		t.Fatalf("停用节点心跳应返回 401，得到 %d", response.Code)
	}

	updated := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d", nodeID), adminToken,
		map[string]any{"name": "edge-renamed", "region": "region-2", "capacity": 120})
	if updated.Code != http.StatusOK {
		t.Fatalf("更新节点元数据应返回 200，得到 %d：%s", updated.Code, updated.Body.String())
	}

	revoked := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/nodes/%d/credentials", nodeID), adminToken, nil)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("撤销节点凭据应返回 204，得到 %d：%s", revoked.Code, revoked.Body.String())
	}
	activeAgain := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d/status", nodeID), adminToken,
		map[string]string{"status": "active"})
	if activeAgain.Code != http.StatusOK {
		t.Fatalf("重新启用节点应返回 200，得到 %d：%s", activeAgain.Code, activeAgain.Body.String())
	}
	if response := heartbeat(newCredential); response.Code != http.StatusUnauthorized {
		t.Fatalf("撤销凭据后心跳应返回 401，得到 %d", response.Code)
	}

	list := testRequest(t, handler, http.MethodGet, "/v1/admin/nodes", adminToken, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("管理员查看节点应返回 200，得到 %d：%s", list.Code, list.Body.String())
	}
	if bytes.Contains(list.Body.Bytes(), []byte(firstCredential)) || bytes.Contains(list.Body.Bytes(), []byte(newCredential)) {
		t.Fatal("节点列表不应返回任何明文凭据")
	}

	var auditCount int
	if err := api.db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_logs WHERE actor_user_id = $1 AND target_type = 'node'`, userID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询节点审计记录失败: %v", err)
	}
	if auditCount < 5 {
		t.Fatalf("节点创建、元数据/状态变更和凭据操作均应审计，记录数仅 %d", auditCount)
	}
}

func TestNodeHealthStatusIsIndependentFromAdminStatus(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, userID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	handler := testRouter(api)
	adminToken := testToken(t, api, userID)
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "health-node", "region": "test", "capacity": 5, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建测试节点失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var payload struct {
		Node struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
			Health string `json:"health_status"`
		} `json:"node"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	if payload.Node.Health != "offline" {
		t.Fatalf("从未心跳的节点应为 offline，得到 %q", payload.Node.Health)
	}

	listHealth := func() (adminNode struct {
		Status string `json:"status"`
		Health string `json:"health_status"`
	}) {
		t.Helper()
		response := testRequest(t, handler, http.MethodGet, "/v1/admin/nodes", adminToken, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("查询节点失败，得到 %d：%s", response.Code, response.Body.String())
		}
		var nodes []json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &nodes); err != nil || len(nodes) != 1 {
			t.Fatalf("解析节点列表失败或节点数量不符：%s (%v)", response.Body.String(), err)
		}
		if err := json.Unmarshal(nodes[0], &adminNode); err != nil {
			t.Fatalf("解析节点状态失败: %v", err)
		}
		return adminNode
	}

	if _, err := api.db.Exec(ctx,
		`UPDATE nodes SET last_heartbeat_at = NOW() - INTERVAL '91 seconds' WHERE id = $1`, payload.Node.ID,
	); err != nil {
		t.Fatalf("设置过期心跳失败: %v", err)
	}
	if got := listHealth(); got.Health != "offline" {
		t.Fatalf("91 秒前的心跳应为 offline，得到 %q", got.Health)
	}
	if _, err := api.db.Exec(ctx,
		`UPDATE nodes SET last_heartbeat_at = NOW() - INTERVAL '89 seconds' WHERE id = $1`, payload.Node.ID,
	); err != nil {
		t.Fatalf("设置新鲜心跳失败: %v", err)
	}
	if got := listHealth(); got.Health != "online" {
		t.Fatalf("89 秒前的心跳应为 online，得到 %q", got.Health)
	}

	maintenance := testRequest(t, handler, http.MethodPatch,
		fmt.Sprintf("/v1/admin/nodes/%d/status", payload.Node.ID), adminToken,
		map[string]string{"status": "maintenance"})
	if maintenance.Code != http.StatusOK {
		t.Fatalf("设置维护状态失败，得到 %d：%s", maintenance.Code, maintenance.Body.String())
	}
	response := testRequest(t, handler, http.MethodPost, "/v1/node/heartbeat", payload.Credential, nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("维护节点应接受有效心跳，得到 %d：%s", response.Code, response.Body.String())
	}
	if got := listHealth(); got.Status != "maintenance" || got.Health != "online" {
		t.Fatalf("心跳不应覆盖管理员维护状态；status=%q health=%q", got.Status, got.Health)
	}

	revoke := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/nodes/%d/credentials", payload.Node.ID), adminToken, nil)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("撤销节点凭据失败，得到 %d：%s", revoke.Code, revoke.Body.String())
	}
	response = testRequest(t, handler, http.MethodPost, "/v1/node/heartbeat", payload.Credential, nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("撤销凭据的心跳应返回 401，得到 %d", response.Code)
	}
}

func TestNodeCapacityCannotDropBelowAssignedDevices(t *testing.T) {
	api, userID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, userID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	handler := testRouter(api)
	adminToken := testToken(t, api, userID)
	invalid := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "invalid-node", "region": "test", "capacity": 0})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("容量为 0 的节点应返回 400，得到 %d", invalid.Code)
	}
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "capacity-node", "region": "test", "capacity": 2, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建测试节点失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var payload struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	nodeID := payload.Node.ID
	for i := byte(20); i < 22; i++ {
		var deviceID int64
		if err := api.db.QueryRow(ctx,
			`INSERT INTO devices (user_id, name, platform, public_key)
			 VALUES ($1, $2, 'windows', $3) RETURNING id`,
			userID, fmt.Sprintf("capacity-device-%d", i), testPublicKey(i),
		).Scan(&deviceID); err != nil {
			t.Fatalf("创建测试设备失败: %v", err)
		}
		if _, err := api.db.Exec(ctx,
			`INSERT INTO node_device_assignments (node_id, device_id) VALUES ($1, $2)`, nodeID, deviceID,
		); err != nil {
			t.Fatalf("分配测试设备失败: %v", err)
		}
	}

	boundary := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d", nodeID), adminToken,
		map[string]int{"capacity": 2})
	if boundary.Code != http.StatusOK {
		t.Fatalf("容量等于已分配设备数时应允许，得到 %d：%s", boundary.Code, boundary.Body.String())
	}
	tooSmall := testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d", nodeID), adminToken,
		map[string]int{"capacity": 1})
	if tooSmall.Code != http.StatusConflict {
		t.Fatalf("容量低于已分配设备数应返回 409，得到 %d：%s", tooSmall.Code, tooSmall.Body.String())
	}
	invalid = testRequest(t, handler, http.MethodPatch, fmt.Sprintf("/v1/admin/nodes/%d", nodeID), adminToken,
		map[string]int{"capacity": 1_000_001})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("超过容量上限的修改应返回 400，得到 %d", invalid.Code)
	}
	var capacity int
	if err := api.db.QueryRow(ctx, `SELECT capacity FROM nodes WHERE id = $1`, nodeID).Scan(&capacity); err != nil {
		t.Fatalf("查询节点容量失败: %v", err)
	}
	if capacity != 2 {
		t.Fatalf("被拒绝的容量修改不应改变数据库，当前容量为 %d", capacity)
	}
}

func TestAdminDeviceAssignmentChecksAndReleasesCapacity(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)
	targetUserID := addTestUser(t, api, "target@example.test", "active")
	otherUserID := addTestUser(t, api, "other@example.test", "active")
	addActiveTestPlan(t, api, targetUserID, 2)
	addActiveTestPlan(t, api, otherUserID, 2)
	firstDeviceID := addTestDevice(t, api, targetUserID, "first", 40)
	secondDeviceID := addTestDevice(t, api, otherUserID, "second", 41)

	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "assignment-node", "region": "test", "capacity": 1, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建节点失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var nodePayload struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &nodePayload); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	nodeID := nodePayload.Node.ID

	// A normal account cannot assign even another user's device.
	denied := testRequest(t, handler, http.MethodPut,
		fmt.Sprintf("/v1/admin/devices/%d/assignment", firstDeviceID),
		testToken(t, api, otherUserID), map[string]int64{"node_id": nodeID})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("普通用户跨账号分配应返回 403，得到 %d：%s", denied.Code, denied.Body.String())
	}

	assign := func(deviceID int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPut,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
			map[string]int64{"node_id": nodeID})
	}
	unassign := func(deviceID int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodDelete,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken, nil)
	}

	first := assign(firstDeviceID)
	if first.Code != http.StatusCreated {
		t.Fatalf("有效设备分配应返回 201，得到 %d：%s", first.Code, first.Body.String())
	}
	full := assign(secondDeviceID)
	if full.Code != http.StatusConflict {
		t.Fatalf("容量已满时分配应返回 409，得到 %d：%s", full.Code, full.Body.String())
	}

	// Removing an assignment releases node capacity without revoking the device.
	removed := unassign(firstDeviceID)
	if removed.Code != http.StatusNoContent {
		t.Fatalf("解除分配应返回 204，得到 %d：%s", removed.Code, removed.Body.String())
	}
	var revoked bool
	if err := api.db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM devices WHERE id = $1`, firstDeviceID).Scan(&revoked); err != nil {
		t.Fatalf("检查设备撤销状态失败: %v", err)
	}
	if revoked {
		t.Fatal("解除节点分配不应撤销设备")
	}
	// The address remains reserved until the node confirms the removal snapshot.
	removalSnapshot := testRequest(t, handler, http.MethodGet, "/v1/node/config", nodePayload.Credential, nil)
	if removalSnapshot.Code != http.StatusOK {
		t.Fatalf("拉取解除分配快照失败：%d %s", removalSnapshot.Code, removalSnapshot.Body.String())
	}
	var removalVersion struct {
		Version int64 `json:"version"`
	}
	if err := json.Unmarshal(removalSnapshot.Body.Bytes(), &removalVersion); err != nil || removalVersion.Version != 2 {
		t.Fatalf("解除分配快照版本应为 2：%s (%v)", removalSnapshot.Body.String(), err)
	}
	acknowledged := testRequest(t, handler, http.MethodPost, "/v1/node/config/ack", nodePayload.Credential,
		map[string]int64{"version": removalVersion.Version})
	if acknowledged.Code != http.StatusNoContent {
		t.Fatalf("确认解除分配快照失败：%d %s", acknowledged.Code, acknowledged.Body.String())
	}
	second := assign(secondDeviceID)
	if second.Code != http.StatusCreated {
		t.Fatalf("释放容量后应能分配第二台设备，得到 %d：%s", second.Code, second.Body.String())
	}

	devices := testRequest(t, handler, http.MethodGet,
		fmt.Sprintf("/v1/admin/users/%d/devices", otherUserID), adminToken, nil)
	if devices.Code != http.StatusOK || bytes.Contains(devices.Body.Bytes(), []byte("public_key")) {
		t.Fatalf("管理员设备列表应显示分配信息但不返回密钥，得到 %d：%s", devices.Code, devices.Body.String())
	}
	var deviceList []map[string]any
	if err := json.Unmarshal(devices.Body.Bytes(), &deviceList); err != nil || len(deviceList) != 1 {
		t.Fatalf("解析管理员设备列表失败：%s (%v)", devices.Body.String(), err)
	}
	if deviceList[0]["assigned_node_id"] != float64(nodeID) || deviceList[0]["assigned_node_status"] != "active" {
		t.Fatalf("设备列表没有显示节点分配状态：%v", deviceList[0])
	}

	if _, err := api.db.Exec(ctx, `UPDATE nodes SET status = 'maintenance' WHERE id = $1`, nodeID); err != nil {
		t.Fatalf("设置节点维护状态失败: %v", err)
	}
	removed = unassign(secondDeviceID)
	if removed.Code != http.StatusNoContent {
		t.Fatalf("解除第二台设备分配应返回 204，得到 %d：%s", removed.Code, removed.Body.String())
	}
	maintenanceDenied := assign(firstDeviceID)
	if maintenanceDenied.Code != http.StatusConflict {
		t.Fatalf("维护节点不可接受新分配，应返回 409，得到 %d：%s", maintenanceDenied.Code, maintenanceDenied.Body.String())
	}

	var auditCount int
	if err := api.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_logs
		 WHERE actor_user_id = $1 AND action IN ('assign_device_node', 'unassign_device_node')`, adminID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询分配审计记录失败: %v", err)
	}
	if auditCount != 4 {
		t.Fatalf("两次分配和两次解除应有 4 条审计记录，实际为 %d", auditCount)
	}
}

func TestDeviceAssignmentRequiresActiveUserAndSubscription(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)

	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "eligibility-node", "region": "test", "capacity": 10, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建节点失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var nodePayload struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &nodePayload); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	nodeID := nodePayload.Node.ID
	assign := func(deviceID int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPut,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
			map[string]int64{"node_id": nodeID})
	}

	noPlanUser := addTestUser(t, api, "no-plan@example.test", "active")
	noPlanDevice := addTestDevice(t, api, noPlanUser, "no-plan", 42)
	if response := assign(noPlanDevice); response.Code != http.StatusForbidden {
		t.Fatalf("无有效订阅的设备应被拒绝，得到 %d：%s", response.Code, response.Body.String())
	}

	suspendedUser := addTestUser(t, api, "suspended@example.test", "suspended")
	addActiveTestPlan(t, api, suspendedUser, 2)
	suspendedDevice := addTestDevice(t, api, suspendedUser, "suspended", 43)
	if response := assign(suspendedDevice); response.Code != http.StatusConflict {
		t.Fatalf("暂停账号设备应被拒绝，得到 %d：%s", response.Code, response.Body.String())
	}

	activeUser := addTestUser(t, api, "active-device@example.test", "active")
	addActiveTestPlan(t, api, activeUser, 2)
	revokedDevice := addTestDevice(t, api, activeUser, "revoked", 44)
	if _, err := api.db.Exec(ctx, `UPDATE devices SET revoked_at = NOW() WHERE id = $1`, revokedDevice); err != nil {
		t.Fatalf("撤销测试设备失败: %v", err)
	}
	if response := assign(revokedDevice); response.Code != http.StatusConflict {
		t.Fatalf("已撤销设备应被拒绝，得到 %d：%s", response.Code, response.Body.String())
	}
}

func TestConcurrentDeviceAssignmentsRespectNodeCapacity(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	addActiveTestPlan(t, api, adminID, 5)
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "concurrent-node", "region": "test", "capacity": 1, "tunnel_cidr": "10.77.0.0/16"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建节点失败，得到 %d：%s", created.Code, created.Body.String())
	}
	var nodePayload struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &nodePayload); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	deviceIDs := []int64{
		addTestDevice(t, api, adminID, "concurrent-a", 45),
		addTestDevice(t, api, adminID, "concurrent-b", 46),
	}
	statuses := make(chan int, len(deviceIDs))
	var wg sync.WaitGroup
	for _, deviceID := range deviceIDs {
		deviceID := deviceID
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := testRequest(t, handler, http.MethodPut,
				fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
				map[string]int64{"node_id": nodePayload.Node.ID})
			statuses <- response.Code
		}()
	}
	wg.Wait()
	close(statuses)
	createdCount, conflictCount := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			createdCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("并发分配返回意外状态码 %d", status)
		}
	}
	if createdCount != 1 || conflictCount != 1 {
		t.Fatalf("容量为 1 时应有一次成功、一次冲突，实际成功 %d、冲突 %d", createdCount, conflictCount)
	}
	var assignedCount int
	if err := api.db.QueryRow(ctx, `SELECT COUNT(*) FROM node_device_assignments WHERE node_id = $1`, nodePayload.Node.ID).Scan(&assignedCount); err != nil {
		t.Fatalf("查询节点分配数失败: %v", err)
	}
	if assignedCount != 1 {
		t.Fatalf("并发分配后节点记录数应为 1，实际为 %d", assignedCount)
	}
}

func TestNodeConfigOutboxSnapshotAndAcknowledgement(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	addActiveTestPlan(t, api, adminID, 4)
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)

	createNode := func(name string) (int64, string) {
		t.Helper()
		response := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
			map[string]any{"name": name, "region": "test", "capacity": 4, "tunnel_cidr": "10.77.0.0/16"})
		if response.Code != http.StatusCreated {
			t.Fatalf("创建节点失败，得到 %d：%s", response.Code, response.Body.String())
		}
		var payload struct {
			Node struct {
				ID int64 `json:"id"`
			} `json:"node"`
			Credential string `json:"credential"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("解析节点响应失败: %v", err)
		}
		return payload.Node.ID, payload.Credential
	}
	nodeA, credentialA := createNode("sync-node-a")
	nodeB, credentialB := createNode("sync-node-b")
	keyA, keyB := testPublicKey(51), testPublicKey(52)
	deviceA := addTestDevice(t, api, adminID, "sync-device-a", 51)
	deviceB := addTestDevice(t, api, adminID, "sync-device-b", 52)
	assign := func(deviceID, nodeID int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPut,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
			map[string]int64{"node_id": nodeID})
	}
	if response := assign(deviceA, nodeA); response.Code != http.StatusCreated {
		t.Fatalf("分配设备到节点 A 失败：%d %s", response.Code, response.Body.String())
	}
	if response := assign(deviceB, nodeB); response.Code != http.StatusCreated {
		t.Fatalf("分配设备到节点 B 失败：%d %s", response.Code, response.Body.String())
	}

	pull := func(credential string) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodGet, "/v1/node/config", credential, nil)
	}
	snapshotA := pull(credentialA)
	if snapshotA.Code != http.StatusOK {
		t.Fatalf("节点 A 拉取快照失败：%d %s", snapshotA.Code, snapshotA.Body.String())
	}
	var configA struct {
		NodeID  int64 `json:"node_id"`
		Version int64 `json:"version"`
		Devices []struct {
			DeviceID      int64  `json:"device_id"`
			PublicKey     string `json:"public_key"`
			Platform      string `json:"platform"`
			TunnelAddress string `json:"tunnel_address"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(snapshotA.Body.Bytes(), &configA); err != nil {
		t.Fatalf("解析节点 A 快照失败: %v", err)
	}
	if configA.NodeID != nodeA || configA.Version != 1 || len(configA.Devices) != 1 ||
		configA.Devices[0].DeviceID != deviceA || configA.Devices[0].PublicKey != keyA ||
		configA.Devices[0].TunnelAddress == "" {
		t.Fatalf("节点 A 快照内容不符合预期：%s", snapshotA.Body.String())
	}
	if bytes.Contains(snapshotA.Body.Bytes(), []byte(keyB)) ||
		bytes.Contains(snapshotA.Body.Bytes(), []byte("password_hash")) ||
		bytes.Contains(snapshotA.Body.Bytes(), []byte("private_key")) {
		t.Fatalf("节点 A 快照包含其他节点设备或敏感字段：%s", snapshotA.Body.String())
	}
	repeated := pull(credentialA)
	if repeated.Code != http.StatusOK || !bytes.Equal(snapshotA.Body.Bytes(), repeated.Body.Bytes()) {
		t.Fatalf("相同状态重复拉取应返回稳定快照：首次 %s，再次 %s", snapshotA.Body.String(), repeated.Body.String())
	}

	snapshotB := pull(credentialB)
	var configB struct {
		NodeID  int64 `json:"node_id"`
		Version int64 `json:"version"`
		Devices []struct {
			DeviceID  int64  `json:"device_id"`
			PublicKey string `json:"public_key"`
		} `json:"devices"`
	}
	if snapshotB.Code != http.StatusOK || json.Unmarshal(snapshotB.Body.Bytes(), &configB) != nil {
		t.Fatalf("节点 B 快照读取失败：%d %s", snapshotB.Code, snapshotB.Body.String())
	}
	if configB.NodeID != nodeB || configB.Version != 1 || len(configB.Devices) != 1 || configB.Devices[0].PublicKey != keyB {
		t.Fatalf("节点 B 不应读取节点 A 的设备：%s", snapshotB.Body.String())
	}

	ack := func(credential string, version int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPost, "/v1/node/config/ack", credential,
			map[string]int64{"version": version})
	}
	if response := ack(credentialA, 2); response.Code != http.StatusConflict {
		t.Fatalf("确认尚不存在的超前版本应返回 409，得到 %d：%s", response.Code, response.Body.String())
	}
	for i := 0; i < 2; i++ {
		if response := ack(credentialA, 1); response.Code != http.StatusNoContent {
			t.Fatalf("确认并重复确认版本 1 应成功，得到 %d：%s", response.Code, response.Body.String())
		}
	}

	unassign := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceA), adminToken, nil)
	if unassign.Code != http.StatusNoContent {
		t.Fatalf("解除节点 A 分配失败：%d %s", unassign.Code, unassign.Body.String())
	}
	updatedSnapshot := pull(credentialA)
	if updatedSnapshot.Code != http.StatusOK {
		t.Fatalf("拉取更新快照失败：%d %s", updatedSnapshot.Code, updatedSnapshot.Body.String())
	}
	if err := json.Unmarshal(updatedSnapshot.Body.Bytes(), &configA); err != nil {
		t.Fatalf("解析更新快照失败: %v", err)
	}
	if configA.Version != 2 || len(configA.Devices) != 0 {
		t.Fatalf("解除分配后期望版本应递增且快照为空：%s", updatedSnapshot.Body.String())
	}
	if response := ack(credentialA, 2); response.Code != http.StatusNoContent {
		t.Fatalf("确认最新版本应成功，得到 %d：%s", response.Code, response.Body.String())
	}
	if response := ack(credentialA, 1); response.Code != http.StatusConflict {
		t.Fatalf("旧版本不得回退确认状态，得到 %d：%s", response.Code, response.Body.String())
	}

	var outboxCount int
	if err := api.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM node_config_outbox WHERE node_id = $1`, nodeA,
	).Scan(&outboxCount); err != nil {
		t.Fatalf("查询节点 A outbox 失败: %v", err)
	}
	if outboxCount != 2 {
		t.Fatalf("节点 A 分配和解除应各有一条 outbox 记录，实际为 %d", outboxCount)
	}
	var desiredVersion, ackVersion int64
	var syncPending bool
	var lastSyncAt *time.Time
	if err := api.db.QueryRow(ctx,
		`SELECT desired_config_version, acknowledged_config_version,
		        acknowledged_config_version < desired_config_version, last_sync_at
		 FROM nodes WHERE id = $1`, nodeA,
	).Scan(&desiredVersion, &ackVersion, &syncPending, &lastSyncAt); err != nil {
		t.Fatalf("查询节点同步状态失败: %v", err)
	}
	if desiredVersion != 2 || ackVersion != 2 || syncPending || lastSyncAt == nil {
		t.Fatalf("节点同步状态不正确：desired=%d ack=%d pending=%v last_sync=%v", desiredVersion, ackVersion, syncPending, lastSyncAt)
	}

	revoke := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/nodes/%d/credentials", nodeA), adminToken, nil)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("撤销节点凭据失败：%d %s", revoke.Code, revoke.Body.String())
	}
	if response := pull(credentialA); response.Code != http.StatusUnauthorized {
		t.Fatalf("撤销凭据后节点不得继续拉取配置，得到 %d", response.Code)
	}
	if response := ack(credentialA, 2); response.Code != http.StatusUnauthorized {
		t.Fatalf("撤销凭据后节点不得确认配置，得到 %d", response.Code)
	}
}

func TestTunnelAddressPoolBoundariesUniquenessAndConcurrency(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	addActiveTestPlan(t, api, adminID, 20)
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)
	createNode := func(name string, capacity int, cidr string) (int64, string, int) {
		t.Helper()
		response := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
			map[string]any{"name": name, "region": "test", "capacity": capacity, "tunnel_cidr": cidr})
		var result struct {
			Node struct {
				ID               int64 `json:"id"`
				AddressPoolSize  int64 `json:"address_pool_size"`
				AddressAvailable int64 `json:"address_available"`
			} `json:"node"`
			Credential string `json:"credential"`
		}
		if response.Code == http.StatusCreated {
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatalf("解析节点响应失败: %v", err)
			}
		}
		return result.Node.ID, result.Credential, response.Code
	}
	if _, _, status := createNode("too-large-for-subnet", 2, "10.88.0.0/30"); status != http.StatusBadRequest {
		t.Fatalf("/30 只有一个可用设备地址，容量 2 应返回 400，得到 %d", status)
	}
	nodeID, _, status := createNode("boundary-node", 5, "10.88.0.0/29")
	if status != http.StatusCreated {
		t.Fatalf("/29 配置 5 个地址应成功，得到 %d", status)
	}

	deviceIDs := make([]int64, 5)
	for i := range deviceIDs {
		deviceIDs[i] = addTestDevice(t, api, adminID, fmt.Sprintf("boundary-%d", i), byte(80+i))
	}
	addresses := make(map[string]bool)
	for i, deviceID := range deviceIDs {
		response := testRequest(t, handler, http.MethodPut,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
			map[string]int64{"node_id": nodeID})
		if response.Code != http.StatusCreated {
			t.Fatalf("分配边界地址 %d 失败：%d %s", i, response.Code, response.Body.String())
		}
		var assignment struct {
			TunnelAddress string `json:"tunnel_address"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &assignment); err != nil {
			t.Fatalf("解析地址分配响应失败: %v", err)
		}
		expected := fmt.Sprintf("10.88.0.%d", i+2)
		if assignment.TunnelAddress != expected {
			t.Fatalf("地址应避开网络、网关和广播地址，期望 %s，得到 %s", expected, assignment.TunnelAddress)
		}
		if addresses[assignment.TunnelAddress] {
			t.Fatalf("节点地址重复分配：%s", assignment.TunnelAddress)
		}
		addresses[assignment.TunnelAddress] = true
	}
	if len(addresses) != 5 || addresses["10.88.0.0"] || addresses["10.88.0.1"] || addresses["10.88.0.7"] {
		t.Fatalf("/29 地址池边界或唯一性错误：%v", addresses)
	}

	// Two simultaneous allocators share a /29 pool and must receive distinct IPs.
	concurrentNodeID, _, status := createNode("concurrent-address-node", 2, "10.89.0.0/29")
	if status != http.StatusCreated {
		t.Fatalf("创建并发地址节点失败：%d", status)
	}
	concurrentDevices := []int64{
		addTestDevice(t, api, adminID, "address-concurrent-a", 90),
		addTestDevice(t, api, adminID, "address-concurrent-b", 91),
	}
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, len(concurrentDevices))
	for _, deviceID := range concurrentDevices {
		deviceID := deviceID
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- testRequest(t, handler, http.MethodPut,
				fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
				map[string]int64{"node_id": concurrentNodeID})
		}()
	}
	wg.Wait()
	close(results)
	concurrentAddresses := map[string]bool{}
	for response := range results {
		if response.Code != http.StatusCreated {
			t.Fatalf("并发地址分配应成功，得到 %d：%s", response.Code, response.Body.String())
		}
		var item struct {
			TunnelAddress string `json:"tunnel_address"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &item); err != nil {
			t.Fatalf("解析并发地址响应失败: %v", err)
		}
		concurrentAddresses[item.TunnelAddress] = true
	}
	if len(concurrentAddresses) != 2 {
		t.Fatalf("并发分配应得到两个不同地址，实际为 %v", concurrentAddresses)
	}
}

func TestTunnelAddressNotReusedUntilRemovalAcknowledged(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := api.db.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	addActiveTestPlan(t, api, adminID, 5)
	adminToken := testToken(t, api, adminID)
	handler := testRouter(api)
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "release-node", "region": "test", "capacity": 1, "tunnel_cidr": "10.90.0.0/30"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建 /30 测试节点失败：%d %s", created.Code, created.Body.String())
	}
	var node struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &node); err != nil {
		t.Fatalf("解析节点响应失败: %v", err)
	}
	first := addTestDevice(t, api, adminID, "release-first", 101)
	second := addTestDevice(t, api, adminID, "release-second", 102)
	assign := func(deviceID int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPut,
			fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
			map[string]int64{"node_id": node.Node.ID})
	}
	firstResult := assign(first)
	if firstResult.Code != http.StatusCreated {
		t.Fatalf("首次地址分配失败：%d %s", firstResult.Code, firstResult.Body.String())
	}
	var firstAddress struct {
		TunnelAddress string `json:"tunnel_address"`
	}
	if err := json.Unmarshal(firstResult.Body.Bytes(), &firstAddress); err != nil || firstAddress.TunnelAddress != "10.90.0.2" {
		t.Fatalf("/30 的唯一设备地址应为 .2：%s (%v)", firstResult.Body.String(), err)
	}
	ack := func(version int64) *httptest.ResponseRecorder {
		t.Helper()
		return testRequest(t, handler, http.MethodPost, "/v1/node/config/ack", node.Credential,
			map[string]int64{"version": version})
	}
	if response := ack(1); response.Code != http.StatusNoContent {
		t.Fatalf("确认初始配置失败：%d %s", response.Code, response.Body.String())
	}
	removed := testRequest(t, handler, http.MethodDelete,
		fmt.Sprintf("/v1/admin/devices/%d/assignment", first), adminToken, nil)
	if removed.Code != http.StatusNoContent {
		t.Fatalf("解除分配失败：%d %s", removed.Code, removed.Body.String())
	}
	blocked := assign(second)
	if blocked.Code != http.StatusConflict || !strings.Contains(blocked.Body.String(), "node_address_pool_exhausted") {
		t.Fatalf("未确认移除前地址必须保留，期望地址池冲突，得到 %d：%s", blocked.Code, blocked.Body.String())
	}
	var state string
	var releaseVersion int64
	if err := api.db.QueryRow(ctx,
		`SELECT state, release_version FROM node_tunnel_addresses WHERE node_id = $1 AND device_id = $2`,
		node.Node.ID, first,
	).Scan(&state, &releaseVersion); err != nil || state != "releasing" || releaseVersion != 2 {
		t.Fatalf("解除分配地址应保留到版本 2 确认：state=%s version=%d err=%v", state, releaseVersion, err)
	}
	if response := ack(2); response.Code != http.StatusNoContent {
		t.Fatalf("确认移除版本失败：%d %s", response.Code, response.Body.String())
	}
	reused := assign(second)
	if reused.Code != http.StatusCreated {
		t.Fatalf("确认移除后应能复用地址：%d %s", reused.Code, reused.Body.String())
	}
	var secondAddress struct {
		TunnelAddress string `json:"tunnel_address"`
	}
	if err := json.Unmarshal(reused.Body.Bytes(), &secondAddress); err != nil || secondAddress.TunnelAddress != firstAddress.TunnelAddress {
		t.Fatalf("确认移除后应复用释放地址，首次=%s 再次=%s err=%v", firstAddress.TunnelAddress, secondAddress.TunnelAddress, err)
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
