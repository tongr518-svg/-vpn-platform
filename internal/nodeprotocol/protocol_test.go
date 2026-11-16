package nodeprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestV1CrossLanguageVector(t *testing.T) {
	var vector struct {
		Snapshot        Snapshot `json:"snapshot"`
		Canonical       string   `json:"canonical_snapshot"`
		Digest          string   `json:"snapshot_digest"`
		Approval        Approval `json:"approval"`
		ApprovalMessage string   `json:"approval_message"`
		PublicKey       string   `json:"public_key"`
	}
	data, err := os.ReadFile("testdata/v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if got := string(CanonicalSnapshot(vector.Snapshot)); got != vector.Canonical {
		t.Fatalf("canonical bytes differ\nwant: %q\n got: %q", vector.Canonical, got)
	}
	if got := SnapshotDigest(vector.Snapshot); got != vector.Digest {
		t.Fatalf("digest = %s, want %s", got, vector.Digest)
	}
	if got := string(ApprovalMessage(vector.Approval)); got != vector.ApprovalMessage {
		t.Fatalf("approval message differs\nwant: %q\n got: %q", vector.ApprovalMessage, got)
	}
	if err := ValidateSnapshot(vector.Snapshot); err != nil {
		t.Fatalf("vector snapshot invalid: %v", err)
	}
	keyBytes, err := decodePublicKey(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyApproval(ed25519.PublicKey(keyBytes), vector.Approval, 42, 7, vector.Digest, time.Date(2025, 1, 2, 3, 5, 0, 0, time.UTC)); err != nil {
		t.Fatalf("vector signature rejected: %v", err)
	}
}

func decodePublicKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

func TestVerifyApprovalRejectsWrongNodeVersionDigestAndExpiry(t *testing.T) {
	data, err := os.ReadFile("testdata/v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Approval  Approval `json:"approval"`
		PublicKey string   `json:"public_key"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := decodePublicKey(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PublicKey(keyBytes)
	now := time.Date(2025, 1, 2, 3, 5, 0, 0, time.UTC)
	checks := []struct {
		name    string
		nodeID  int64
		version int64
		digest  string
		now     time.Time
	}{
		{name: "node", nodeID: 43, version: 7, digest: vector.Approval.CandidateDigest, now: now},
		{name: "version", nodeID: 42, version: 8, digest: vector.Approval.CandidateDigest, now: now},
		{name: "digest", nodeID: 42, version: 7, digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now: now},
		{name: "expired", nodeID: 42, version: 7, digest: vector.Approval.CandidateDigest, now: vector.Approval.ExpiresAt},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := VerifyApproval(key, vector.Approval, check.nodeID, check.version, check.digest, check.now); err == nil {
				t.Fatal("expected verification failure")
			}
		})
	}
	tampered := vector.Approval
	tampered.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	if err := VerifyApproval(key, tampered, 42, 7, tampered.CandidateDigest, now); err == nil {
		t.Fatal("tampered signature should be rejected")
	}
}
