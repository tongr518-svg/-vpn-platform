package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/nodeprotocol"
)

type fakeWireGuard struct {
	current           []byte
	showCalls         int
	setCalls          int
	failCandidateOnce bool
}

func (f *fakeWireGuard) ShowConfig(_ context.Context, iface string) ([]byte, error) {
	f.showCalls++
	if iface != testInterfaceName {
		return nil, errors.New("unexpected interface")
	}
	return append([]byte(nil), f.current...), nil
}

func (f *fakeWireGuard) SetConfig(_ context.Context, iface, path string) error {
	f.setCalls++
	if iface != testInterfaceName {
		return errors.New("unexpected interface")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if f.failCandidateOnce && strings.HasSuffix(path, "wg-lab.conf") {
		f.failCandidateOnce = false
		return errors.New("injected apply failure")
	}
	f.current = append([]byte(nil), data...)
	return nil
}

func TestAgentDryRunValidatesAndDiffsWithoutSystemCommands(t *testing.T) {
	snapshot, approval, signingKey := signedFixture(t)
	var verifyCalls, ackCalls int
	server := approvalServer(t, snapshot, approval, &verifyCalls, &ackCalls)
	defer server.Close()
	a, keyText, logs := testAgent(t, server, snapshot.NodeID, false)
	fake := &fakeWireGuard{}
	a.executor = fake
	a.client = server.Client()

	if err := a.run(context.Background()); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if fake.showCalls != 0 || fake.setCalls != 0 || verifyCalls != 0 || ackCalls != 0 {
		t.Fatalf("dry-run must not execute commands or consume approval: fake=%+v verify=%d ack=%d", fake, verifyCalls, ackCalls)
	}
	if strings.Contains(logs.String(), keyText) || strings.Contains(logs.String(), "node_test_secret") || strings.Contains(logs.String(), approval.Signature) {
		t.Fatal("logs contain a private key, credential, or signature")
	}
	if len(signingKey) == 0 {
		t.Fatal("test signing key was not initialized")
	}
}

func TestAgentAppliesApprovedConfigThenConfirmsAndRetriesIdempotently(t *testing.T) {
	snapshot, approval, _ := signedFixture(t)
	var verifyCalls, ackCalls int
	server := approvalServer(t, snapshot, approval, &verifyCalls, &ackCalls)
	defer server.Close()
	a, keyText, logs := testAgent(t, server, snapshot.NodeID, true)
	old := []byte("[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytesFilled(8)) + "\n")
	fake := &fakeWireGuard{current: old}
	a.executor = fake
	a.client = server.Client()

	if err := a.run(context.Background()); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if fake.showCalls != 1 || fake.setCalls != 1 || verifyCalls != 1 || ackCalls != 1 {
		t.Fatalf("unexpected apply lifecycle: fake=%+v verify=%d ack=%d", fake, verifyCalls, ackCalls)
	}
	configBytes, err := os.ReadFile(a.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configBytes), "AllowedIPs = 10.77.0.2/32") || !strings.Contains(string(configBytes), keyText) {
		t.Fatalf("rendered config missing expected local key or assigned address")
	}
	info, err := os.Stat(a.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && info.Mode().Perm() != 0600 {
		t.Fatalf("config must be mode 0600, mode=%v", info.Mode())
	}
	backup, err := os.ReadFile(a.config.ConfigFile + ".previous")
	if err != nil || !strings.EqualFold(string(backup), string(old)) {
		t.Fatalf("previous config backup mismatch: %v", err)
	}
	if strings.Contains(logs.String(), keyText) || strings.Contains(logs.String(), "node_test_secret") {
		t.Fatal("logs leaked secret")
	}

	if err := a.run(context.Background()); err != nil {
		t.Fatalf("same-version retry should be idempotent: %v", err)
	}
	if fake.setCalls != 1 || verifyCalls != 1 || ackCalls != 1 {
		t.Fatalf("same-version retry repeated mutation: %+v", fake)
	}
}

func TestAgentRejectsMissingExpiredOrMismatchedApprovalBeforeApply(t *testing.T) {
	snapshot, valid, signingKey := signedFixture(t)
	tests := []struct {
		name     string
		approval nodeprotocol.Approval
		status   int
	}{
		{name: "expired", approval: resignApproval(valid, signingKey, func(a *nodeprotocol.Approval) {
			a.IssuedAt = time.Now().Add(-20 * time.Minute)
			a.ExpiresAt = time.Now().Add(-10 * time.Minute)
		})},
		{name: "wrong node", approval: resignApproval(valid, signingKey, func(a *nodeprotocol.Approval) { a.NodeID++ })},
		{name: "wrong digest", approval: resignApproval(valid, signingKey, func(a *nodeprotocol.Approval) { a.CandidateDigest = strings.Repeat("0", 64) })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var verifyCalls, ackCalls int
			server := approvalServer(t, snapshot, test.approval, &verifyCalls, &ackCalls)
			defer server.Close()
			a, _, _ := testAgent(t, server, snapshot.NodeID, true)
			fake := &fakeWireGuard{}
			a.executor = fake
			a.client = server.Client()
			if err := a.run(context.Background()); err == nil {
				t.Fatal("invalid approval should be rejected")
			}
			if fake.showCalls != 0 || fake.setCalls != 0 || verifyCalls != 0 || ackCalls != 0 {
				t.Fatalf("invalid approval triggered apply: fake=%+v verify=%d ack=%d", fake, verifyCalls, ackCalls)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		var verifyCalls, ackCalls int
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/node/config" {
				_ = json.NewEncoder(w).Encode(snapshot)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()
		a, _, _ := testAgent(t, server, snapshot.NodeID, true)
		fake := &fakeWireGuard{}
		a.executor = fake
		a.client = server.Client()
		if err := a.run(context.Background()); err == nil {
			t.Fatal("missing approval should be rejected")
		}
		if fake.showCalls != 0 || fake.setCalls != 0 || verifyCalls != 0 || ackCalls != 0 {
			t.Fatal("missing approval triggered apply")
		}
	})
}

func TestAgentApplyFailureRestoresPreviousConfig(t *testing.T) {
	snapshot, approval, _ := signedFixture(t)
	var verifyCalls, ackCalls int
	server := approvalServer(t, snapshot, approval, &verifyCalls, &ackCalls)
	defer server.Close()
	a, _, _ := testAgent(t, server, snapshot.NodeID, true)
	old := []byte("[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytesFilled(7)) + "\n")
	fake := &fakeWireGuard{current: old, failCandidateOnce: true}
	a.executor = fake
	a.client = server.Client()
	if err := a.run(context.Background()); errorCategory(err) != "apply_failed_rolled_back" {
		t.Fatalf("expected rolled-back apply error, got %v", err)
	}
	if string(fake.current) != string(old) {
		t.Fatal("failed apply did not restore interface config")
	}
	if fake.setCalls != 2 || verifyCalls != 0 || ackCalls != 0 {
		t.Fatalf("rollback or approval ordering wrong: fake=%+v verify=%d ack=%d", fake, verifyCalls, ackCalls)
	}
	if _, err := os.Stat(a.config.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("managed candidate file should be removed after rollback: %v", err)
	}
}

func TestAgentRollsBackWhenApprovalBecomesStaleBeforeConfirmation(t *testing.T) {
	snapshot, approval, _ := signedFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/node/config":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/v1/node/config/approval":
			_ = json.NewEncoder(w).Encode(map[string]any{"approval": approval, "applied": false})
		case "/v1/node/config/approval/verify":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "approval_candidate_stale"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a, _, _ := testAgent(t, server, snapshot.NodeID, true)
	old := []byte("[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytesFilled(7)) + "\n")
	fake := &fakeWireGuard{current: old}
	a.executor = fake
	a.client = server.Client()
	if err := a.run(context.Background()); errorCategory(err) != "approval_rejected_or_replayed" {
		t.Fatalf("stale confirmation should fail, got %v", err)
	}
	if string(fake.current) != string(old) || fake.setCalls != 2 {
		t.Fatalf("stale candidate should be rolled back: setCalls=%d", fake.setCalls)
	}
	if _, err := os.Stat(a.journalPath()); !os.IsNotExist(err) {
		t.Fatalf("permanently rejected application journal should be cleared: %v", err)
	}
}

func TestInvalidCandidateConfigDoesNotReplaceManagedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-lab.conf")
	old, err := renderWireGuardConfig(sampleSnapshot(), base64.StdEncoding.EncodeToString(bytesFilled(6)))
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteConfig(path, old); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteConfig(path, []byte("[Interface]\nPrivateKey = not-a-key\n")); err == nil {
		t.Fatal("invalid temporary config should be rejected")
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(old) {
		t.Fatalf("invalid candidate replaced the previous config: %v", err)
	}
}

func TestAgentRecoversAppliedButUnconfirmedJournal(t *testing.T) {
	snapshot, approval, _ := signedFixture(t)
	var firstVerify, firstAck int
	failedConfirm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/node/config" {
			_ = json.NewEncoder(w).Encode(snapshot)
			return
		}
		if r.URL.Path == "/v1/node/config/approval" {
			_ = json.NewEncoder(w).Encode(map[string]any{"approval": approval, "applied": false})
			return
		}
		if r.URL.Path == "/v1/node/config/approval/verify" {
			firstVerify++
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	}))
	a, _, _ := testAgent(t, failedConfirm, snapshot.NodeID, true)
	fake := &fakeWireGuard{}
	a.executor = fake
	a.client = failedConfirm.Client()
	if err := a.run(context.Background()); err == nil {
		t.Fatal("confirmation failure should be reported")
	}
	failedConfirm.Close()
	if fake.setCalls != 1 || firstVerify != 1 || firstAck != 0 {
		t.Fatalf("first apply lifecycle unexpected: %+v", fake)
	}
	journal, err := a.readJournal()
	if err != nil || journal.Phase != "applied" {
		t.Fatalf("applied state journal missing: %+v %v", journal, err)
	}

	var verifyCalls, ackCalls int
	second := approvalServer(t, snapshot, approval, &verifyCalls, &ackCalls)
	defer second.Close()
	a.config.BaseURL = strings.TrimRight(second.URL, "/")
	a.client = second.Client()
	if err := a.run(context.Background()); err != nil {
		t.Fatalf("journal recovery failed: %v", err)
	}
	if fake.setCalls != 1 || verifyCalls != 1 || ackCalls != 1 {
		t.Fatalf("recovery reapplied config or failed confirmation: %+v verify=%d ack=%d", fake, verifyCalls, ackCalls)
	}
	if _, err := os.Stat(a.journalPath()); !os.IsNotExist(err) {
		t.Fatalf("recovered journal should be cleared: %v", err)
	}
}

func TestAgentRejectsInvalidSnapshotWithoutApplying(t *testing.T) {
	snapshot, approval, _ := signedFixture(t)
	snapshot.Devices[0].TunnelAddress = "10.77.0.1"
	approval.CandidateDigest = nodeprotocol.SnapshotDigest(snapshot)
	var verifyCalls, ackCalls int
	server := approvalServer(t, snapshot, approval, &verifyCalls, &ackCalls)
	defer server.Close()
	a, _, _ := testAgent(t, server, snapshot.NodeID, true)
	fake := &fakeWireGuard{}
	a.executor = fake
	a.client = server.Client()
	if err := a.run(context.Background()); err == nil {
		t.Fatal("invalid snapshot should be rejected")
	}
	if fake.showCalls != 0 || fake.setCalls != 0 {
		t.Fatal("invalid snapshot touched system executor")
	}
}

func TestAgentRequiresRestrictedLocalPrivateKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX key-file permission enforcement is tested on Linux")
	}
	seed := bytesFilled(4)
	private := ed25519.NewKeyFromSeed(seed)
	base := config{BaseURL: "https://control.example.test", NodeID: 42, Credential: "node", PinnedKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), StateDirectory: filepath.Join(t.TempDir(), "state"), ConfigFile: filepath.Join(t.TempDir(), "wg-lab.conf")}
	if _, err := newAgent(base, nil); errorCategory(err) != "private_key_file_required" {
		t.Fatalf("missing key file should fail, got %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(bytesFilled(9))+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	base.PrivateKeyFile = keyPath
	if _, err := newAgent(base, nil); errorCategory(err) != "private_key_file_permissions_invalid" {
		t.Fatalf("over-permissive key should fail, got %v", err)
	}
}

func TestAgentRejectsNonLabInterface(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "wg-lab.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(bytesFilled(8))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(bytesFilled(1)).Public().(ed25519.PublicKey)
	_, err := newAgent(config{
		BaseURL: "https://control.example.test", NodeID: 42, Credential: "node",
		PinnedKey: base64.StdEncoding.EncodeToString(public), StateDirectory: filepath.Join(root, "state"),
		PrivateKeyFile: keyPath, ConfigFile: filepath.Join(root, "wg-lab.conf"), InterfaceName: "wg0", Apply: true,
	}, nil)
	if errorCategory(err) != "unsafe_interface_rejected" {
		t.Fatalf("only wg-lab may be configured, got %v", err)
	}
}

func TestAgentRequiresHTTPSForRemoteControlPlane(t *testing.T) {
	if _, err := parseBaseURL("http://control.example.test"); err == nil {
		t.Fatal("remote HTTP must be rejected")
	}
	if _, err := parseBaseURL("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("loopback development URL should be accepted: %v", err)
	}
}

func signedFixture(t *testing.T) (nodeprotocol.Snapshot, nodeprotocol.Approval, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytesFilled(1))
	snapshot := sampleSnapshot()
	approval := sampleApproval(snapshot, privateKey)
	return snapshot, approval, privateKey
}

func approvalServer(t *testing.T, snapshot nodeprotocol.Snapshot, approval nodeprotocol.Approval, verifyCalls, ackCalls *int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node_test_secret_0123456789abcdef" {
			t.Errorf("node credential missing or changed")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/node/config":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/v1/node/config/approval":
			_ = json.NewEncoder(w).Encode(map[string]any{"approval": approval, "applied": false})
		case "/v1/node/config/approval/verify":
			*verifyCalls++
			var body struct {
				Approval nodeprotocol.Approval `json:"approval"`
				Applied  bool                  `json:"applied"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode apply confirmation: %v", err)
			}
			if !body.Applied || body.Approval.Nonce != approval.Nonce {
				t.Errorf("confirmation must follow apply and match approval")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"verified": true, "node_id": snapshot.NodeID, "candidate_version": snapshot.Version, "applied": true})
		case "/v1/node/config/ack":
			*ackCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
}

func testAgent(t *testing.T, server *httptest.Server, nodeID int64, apply bool) (*agent, string, *strings.Builder) {
	t.Helper()
	root := t.TempDir()
	keyText := base64.StdEncoding.EncodeToString(bytesFilled(0x2a))
	keyPath := filepath.Join(root, "wg-lab.key")
	if err := os.WriteFile(keyPath, []byte(keyText+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	seed := bytesFilled(1)
	privateKey := ed25519.NewKeyFromSeed(seed)
	var logs strings.Builder
	a, err := newAgent(config{
		BaseURL: server.URL, NodeID: nodeID, Credential: "node_test_secret_0123456789abcdef",
		PinnedKey:      base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		StateDirectory: filepath.Join(root, "state"), PrivateKeyFile: keyPath,
		ConfigFile: filepath.Join(root, "wg-lab.conf"), InterfaceName: testInterfaceName, Apply: apply,
	}, &logs)
	if err != nil {
		t.Fatal(err)
	}
	if apply {
		// Apply-path tests run entirely through the fake executor, including on
		// Windows developer machines; CI also runs them on Linux.
		a.platform = "linux"
	}
	return a, keyText, &logs
}

func resignApproval(approval nodeprotocol.Approval, key ed25519.PrivateKey, mutate func(*nodeprotocol.Approval)) nodeprotocol.Approval {
	mutate(&approval)
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, nodeprotocol.ApprovalMessage(approval)))
	return approval
}

func sampleSnapshot() nodeprotocol.Snapshot {
	return nodeprotocol.Snapshot{
		NodeID: 42, Version: 7, TunnelCIDR: "10.77.0.0/24", GatewayAddress: "10.77.0.1",
		Devices: []nodeprotocol.Device{{DeviceID: 9, PublicKey: base64.StdEncoding.EncodeToString(bytesFilled(3)), Platform: "windows", AssignedAt: time.Now().UTC().Truncate(time.Second), TunnelAddress: "10.77.0.2"}},
	}
}

func sampleApproval(snapshot nodeprotocol.Snapshot, key ed25519.PrivateKey) nodeprotocol.Approval {
	now := time.Now().UTC().Truncate(time.Second)
	approval := nodeprotocol.Approval{
		ID: 1, NodeID: snapshot.NodeID, CandidateVersion: snapshot.Version,
		CandidateDigest: nodeprotocol.SnapshotDigest(snapshot),
		Nonce:           base64.RawURLEncoding.EncodeToString(bytesFilled(5)), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, nodeprotocol.ApprovalMessage(approval)))
	return approval
}

func bytesFilled(value byte) []byte {
	result := make([]byte, 32)
	for i := range result {
		result[i] = value
	}
	return result
}
