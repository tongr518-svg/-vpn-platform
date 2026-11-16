package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/nodeprotocol"
)

func TestAgentVerifiesThenConsumesApprovalReadOnly(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	snapshot := sampleSnapshot()
	approval := sampleApproval(snapshot, privateKey)
	var calls []string
	consumed := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node_test_secret_0123456789abcdef" {
			t.Errorf("node credential missing or changed")
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/node/config":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/v1/node/config/approval":
			_ = json.NewEncoder(w).Encode(map[string]any{"approval": approval, "applied": false})
		case "/v1/node/config/approval/verify":
			var body struct {
				Approval nodeprotocol.Approval `json:"approval"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode verification request: %v", err)
			}
			if body.Approval.Nonce != approval.Nonce {
				t.Errorf("wrong nonce submitted")
			}
			consumed++
			_ = json.NewEncoder(w).Encode(map[string]any{"verified": true, "node_id": snapshot.NodeID, "candidate_version": snapshot.Version, "applied": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	stateDir := filepath.Join(t.TempDir(), "agent-state")
	var logs strings.Builder
	a, err := newAgent(config{
		BaseURL: server.URL, NodeID: snapshot.NodeID,
		Credential:     "node_test_secret_0123456789abcdef",
		PinnedKey:      base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		StateDirectory: stateDir,
	}, &logs)
	if err != nil {
		t.Fatal(err)
	}
	a.client = server.Client()
	a.now = func() time.Time { return time.Now().UTC() }

	if err := a.run(context.Background()); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected one nonce consumption, got %d", consumed)
	}
	if err := a.run(context.Background()); errorCategory(err) != "approval_replayed_locally" {
		t.Fatalf("repeated approval should be rejected locally, got %v", err)
	}
	if consumed != 1 {
		t.Fatalf("replay attempted server consumption: %d", consumed)
	}
	for _, call := range calls {
		if strings.Contains(call, "apply") || strings.Contains(call, "wireguard") {
			t.Fatalf("agent called prohibited operation: %s", call)
		}
	}
	if len(calls) != 5 {
		t.Fatalf("unexpected request sequence: %v", calls)
	}
	if strings.Contains(logs.String(), "node_test_secret") || strings.Contains(logs.String(), approval.Signature) {
		t.Fatal("agent log contains credential or signature material")
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one local nonce marker, entries=%v err=%v", entries, err)
	}
}

func TestAgentRejectsInvalidApprovalBeforeConsumption(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	snapshot := sampleSnapshot()
	approval := sampleApproval(snapshot, privateKey)
	approval.CandidateDigest = strings.Repeat("0", 64)
	verifyCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/node/config":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/v1/node/config/approval":
			_ = json.NewEncoder(w).Encode(map[string]any{"approval": approval, "applied": false})
		case "/v1/node/config/approval/verify":
			verifyCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	a, err := newAgent(config{BaseURL: server.URL, NodeID: snapshot.NodeID, Credential: "node_secret", PinnedKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), StateDirectory: filepath.Join(t.TempDir(), "state")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.client = server.Client()
	if err := a.run(context.Background()); errorCategory(err) != "approval_digest_mismatch" {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	if verifyCalls != 0 {
		t.Fatal("invalid approval was submitted for server-side consumption")
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

func sampleSnapshot() nodeprotocol.Snapshot {
	return nodeprotocol.Snapshot{
		NodeID: 42, Version: 7, TunnelCIDR: "10.77.0.0/24", GatewayAddress: "10.77.0.1",
		Devices: []nodeprotocol.Device{{DeviceID: 9, PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Platform: "windows", AssignedAt: time.Now().UTC().Truncate(time.Second), TunnelAddress: "10.77.0.2"}},
	}
}

func sampleApproval(snapshot nodeprotocol.Snapshot, key ed25519.PrivateKey) nodeprotocol.Approval {
	now := time.Now().UTC().Truncate(time.Second)
	approval := nodeprotocol.Approval{
		ID: 1, NodeID: snapshot.NodeID, CandidateVersion: snapshot.Version,
		CandidateDigest: nodeprotocol.SnapshotDigest(snapshot),
		Nonce:           base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:        now, ExpiresAt: now.Add(5 * time.Minute),
	}
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, nodeprotocol.ApprovalMessage(approval)))
	return approval
}
