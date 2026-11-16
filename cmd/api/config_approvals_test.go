package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func setupConfigApprovalFixture(t *testing.T, api *API, adminID int64) (http.Handler, string, int64, string) {
	t.Helper()
	if _, err := api.db.Exec(context.Background(), `UPDATE users SET role = 'admin' WHERE id = $1`, adminID); err != nil {
		t.Fatalf("设置测试管理员失败: %v", err)
	}
	addActiveTestPlan(t, api, adminID, 5)
	handler := testRouter(api)
	adminToken := testToken(t, api, adminID)
	created := testRequest(t, handler, http.MethodPost, "/v1/admin/nodes", adminToken,
		map[string]any{"name": "approval-test-node", "region": "test", "capacity": 5, "tunnel_cidr": "10.75.0.0/29"})
	if created.Code != http.StatusCreated {
		t.Fatalf("创建审批测试节点失败：%d %s", created.Code, created.Body.String())
	}
	var node struct {
		Node struct {
			ID int64 `json:"id"`
		} `json:"node"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &node); err != nil {
		t.Fatalf("解析审批测试节点响应失败: %v", err)
	}
	deviceID := addTestDevice(t, api, adminID, "approval-test-device", 121)
	assigned := testRequest(t, handler, http.MethodPut,
		fmt.Sprintf("/v1/admin/devices/%d/assignment", deviceID), adminToken,
		map[string]int64{"node_id": node.Node.ID})
	if assigned.Code != http.StatusCreated {
		t.Fatalf("分配审批测试设备失败：%d %s", assigned.Code, assigned.Body.String())
	}
	base := nodeConfigSnapshot{
		NodeID: node.Node.ID, Version: 0, TunnelCIDR: "10.75.0.0/29", GatewayAddress: "10.75.0.1",
		Devices: []nodeConfigDevice{},
	}
	dryRun := testRequest(t, handler, http.MethodPost, "/v1/node/config/dry-run", node.Credential,
		map[string]any{"confirmed_snapshot": base})
	if dryRun.Code != http.StatusOK {
		t.Fatalf("生成审批测试 dry-run 失败：%d %s", dryRun.Code, dryRun.Body.String())
	}
	return handler, node.Credential, node.Node.ID, adminToken
}

func TestNodeConfigApprovalSignatureLifecycle(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	handler, credential, nodeID, adminToken := setupConfigApprovalFixture(t, api, adminID)

	noApproval := testRequest(t, handler, http.MethodGet, "/v1/node/config/approval", credential, nil)
	if noApproval.Code != http.StatusNotFound {
		t.Fatalf("未批准时 Agent 不应取得审批，得到 %d：%s", noApproval.Code, noApproval.Body.String())
	}
	wrongVersion := testRequest(t, handler, http.MethodPost,
		fmt.Sprintf("/v1/admin/nodes/%d/config-approvals", nodeID), adminToken,
		map[string]int64{"candidate_version": 999})
	if wrongVersion.Code != http.StatusConflict {
		t.Fatalf("版本不匹配应返回 409，得到 %d：%s", wrongVersion.Code, wrongVersion.Body.String())
	}
	var ordinaryID int64
	if err := api.db.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, role, status) VALUES ('approval-user@example.test', 'test-hash', 'user', 'active') RETURNING id`,
	).Scan(&ordinaryID); err != nil {
		t.Fatalf("创建普通测试用户失败: %v", err)
	}
	forbidden := testRequest(t, handler, http.MethodPost,
		fmt.Sprintf("/v1/admin/nodes/%d/config-approvals", nodeID), testToken(t, api, ordinaryID),
		map[string]int64{"candidate_version": 1})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("普通用户批准节点配置应返回 403，得到 %d：%s", forbidden.Code, forbidden.Body.String())
	}

	path := fmt.Sprintf("/v1/admin/nodes/%d/config-approvals", nodeID)
	approved := testRequest(t, handler, http.MethodPost, path, adminToken, map[string]int64{"candidate_version": 1})
	if approved.Code != http.StatusCreated {
		t.Fatalf("管理员批准当前 dry-run 应成功，得到 %d：%s", approved.Code, approved.Body.String())
	}
	var response struct {
		Approval nodeConfigApproval `json:"approval"`
		Applied  bool               `json:"applied"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析审批响应失败: %v", err)
	}
	if response.Applied || response.Approval.NodeID != nodeID || response.Approval.CandidateVersion != 1 {
		t.Fatalf("审批响应节点/版本错误或意外应用：%s", approved.Body.String())
	}
	publicKey := api.configSigningKey.Public().(ed25519.PublicKey)
	signature, err := base64.StdEncoding.DecodeString(response.Approval.Signature)
	if err != nil || !ed25519.Verify(publicKey, approvalMessage(response.Approval), signature) {
		t.Fatal("审批签名无法用 Ed25519 公钥验证")
	}
	if response.Approval.Signature == "" {
		t.Fatal("审批响应缺少签名")
	}

	repeatedApproval := testRequest(t, handler, http.MethodPost, path, adminToken, map[string]int64{"candidate_version": 1})
	if repeatedApproval.Code != http.StatusOK || !json.Valid(repeatedApproval.Body.Bytes()) {
		t.Fatalf("重复提交审批应幂等返回现有审批，得到 %d：%s", repeatedApproval.Code, repeatedApproval.Body.String())
	}
	var auditCount int
	if err := api.db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_logs WHERE actor_user_id = $1 AND action = 'approve_node_config'`, adminID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询审批审计失败: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("相同审批重复提交只应写一条审计，实际 %d 条", auditCount)
	}

	keyResponse := testRequest(t, handler, http.MethodGet, "/v1/node/config/signing-key", credential, nil)
	if keyResponse.Code != http.StatusOK || !json.Valid(keyResponse.Body.Bytes()) {
		t.Fatalf("Agent 获取签名公钥失败：%d %s", keyResponse.Code, keyResponse.Body.String())
	}
	approvalResponse := testRequest(t, handler, http.MethodGet, "/v1/node/config/approval", credential, nil)
	if approvalResponse.Code != http.StatusOK {
		t.Fatalf("Agent 获取当前审批失败：%d %s", approvalResponse.Code, approvalResponse.Body.String())
	}
	var packageResponse struct {
		Approval nodeConfigApproval `json:"approval"`
		Applied  bool               `json:"applied"`
	}
	if err := json.Unmarshal(approvalResponse.Body.Bytes(), &packageResponse); err != nil {
		t.Fatalf("解析 Agent 审批包失败: %v", err)
	}
	if packageResponse.Applied || packageResponse.Approval.ID != response.Approval.ID {
		t.Fatalf("Agent 审批包与当前审批不符：%s", approvalResponse.Body.String())
	}
	if !ed25519.Verify(publicKey,
		approvalMessage(packageResponse.Approval), mustDecodeSignature(t, packageResponse.Approval.Signature)) {
		t.Fatal("Agent 获取的审批包签名无效")
	}

	tampered := packageResponse.Approval
	tampered.CandidateVersion++
	bad := testRequest(t, handler, http.MethodPost, "/v1/node/config/approval/verify", credential,
		map[string]any{"approval": tampered})
	if bad.Code != http.StatusConflict {
		t.Fatalf("篡改版本的审批应拒绝，得到 %d：%s", bad.Code, bad.Body.String())
	}

	verified := testRequest(t, handler, http.MethodPost, "/v1/node/config/approval/verify", credential,
		map[string]any{"approval": packageResponse.Approval})
	if verified.Code != http.StatusOK || !json.Valid(verified.Body.Bytes()) {
		t.Fatalf("有效审批验证失败：%d %s", verified.Code, verified.Body.String())
	}
	var verification struct {
		Verified bool `json:"verified"`
		Applied  bool `json:"applied"`
	}
	if err := json.Unmarshal(verified.Body.Bytes(), &verification); err != nil || !verification.Verified || verification.Applied {
		t.Fatalf("审批验证结果错误或发生应用：%s (%v)", verified.Body.String(), err)
	}
	replayed := testRequest(t, handler, http.MethodPost, "/v1/node/config/approval/verify", credential,
		map[string]any{"approval": packageResponse.Approval})
	if replayed.Code != http.StatusConflict || !json.Valid(replayed.Body.Bytes()) {
		t.Fatalf("重复提交审批包应拒绝重放，得到 %d：%s", replayed.Code, replayed.Body.String())
	}

	adminAudit := testRequest(t, handler, http.MethodGet, "/v1/admin/audit-logs", adminToken, nil)
	if adminAudit.Code != http.StatusOK || bytes.Contains(adminAudit.Body.Bytes(), []byte("private_key")) {
		t.Fatalf("审计响应异常或含私钥字段：%d %s", adminAudit.Code, adminAudit.Body.String())
	}
}

func TestNodeConfigApprovalRejectsExpiredSignedPackage(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	handler, credential, nodeID, adminToken := setupConfigApprovalFixture(t, api, adminID)
	approved := testRequest(t, handler, http.MethodPost,
		fmt.Sprintf("/v1/admin/nodes/%d/config-approvals", nodeID), adminToken,
		map[string]int64{"candidate_version": 1})
	if approved.Code != http.StatusCreated {
		t.Fatalf("批准候选版本失败：%d %s", approved.Code, approved.Body.String())
	}
	var result struct {
		Approval nodeConfigApproval `json:"approval"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析审批包失败: %v", err)
	}
	result.Approval.IssuedAt = result.Approval.IssuedAt.Add(-20 * time.Minute)
	result.Approval.ExpiresAt = result.Approval.ExpiresAt.Add(-20 * time.Minute)
	signature := ed25519.Sign(api.configSigningKey, approvalMessage(result.Approval))
	result.Approval.Signature = base64.StdEncoding.EncodeToString(signature)
	if _, err := api.db.Exec(context.Background(),
		`UPDATE node_config_approvals SET approved_at = $1, expires_at = $2, signature = $3 WHERE id = $4`,
		result.Approval.IssuedAt, result.Approval.ExpiresAt, signature, result.Approval.ID,
	); err != nil {
		t.Fatalf("构造过期签名审批失败: %v", err)
	}
	response := testRequest(t, handler, http.MethodPost, "/v1/node/config/approval/verify", credential,
		map[string]any{"approval": result.Approval})
	if response.Code != http.StatusConflict || !bytes.Contains(response.Body.Bytes(), []byte("approval_expired")) {
		t.Fatalf("过期但签名正确的审批应被拒绝，得到 %d：%s", response.Code, response.Body.String())
	}
}

func TestConfigApprovalInvalidatedWhenCandidateSnapshotChanges(t *testing.T) {
	api, adminID, cleanup := testFixture(t)
	defer cleanup()
	handler, credential, nodeID, adminToken := setupConfigApprovalFixture(t, api, adminID)

	approved := testRequest(t, handler, http.MethodPost,
		fmt.Sprintf("/v1/admin/nodes/%d/config-approvals", nodeID), adminToken,
		map[string]int64{"candidate_version": 1})
	if approved.Code != http.StatusCreated {
		t.Fatalf("批准候选版本失败：%d %s", approved.Code, approved.Body.String())
	}
	var packageResponse struct {
		Approval nodeConfigApproval `json:"approval"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &packageResponse); err != nil {
		t.Fatalf("解析审批包失败: %v", err)
	}
	if _, err := api.db.Exec(context.Background(),
		`UPDATE devices SET public_key = $1 WHERE id = (SELECT device_id FROM node_device_assignments WHERE node_id = $2)`,
		testPublicKey(122), nodeID,
	); err != nil {
		t.Fatalf("模拟同版本候选快照变化失败: %v", err)
	}

	current := testRequest(t, handler, http.MethodGet, "/v1/node/config/approval", credential, nil)
	if current.Code != http.StatusNotFound {
		t.Fatalf("候选版本变化后旧审批不应再提供，得到 %d：%s", current.Code, current.Body.String())
	}
	verify := testRequest(t, handler, http.MethodPost, "/v1/node/config/approval/verify", credential,
		map[string]any{"approval": packageResponse.Approval})
	if verify.Code != http.StatusConflict || !json.Valid(verify.Body.Bytes()) {
		t.Fatalf("旧候选审批验证应返回冲突，得到 %d：%s", verify.Code, verify.Body.String())
	}
}

func mustDecodeSignature(t *testing.T, encoded string) []byte {
	t.Helper()
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("解码审批签名失败: %v", err)
	}
	return signature
}
