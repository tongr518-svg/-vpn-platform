package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-platform/internal/nodeprotocol"
)

type config struct {
	BaseURL        string
	NodeID         int64
	Credential     string
	PinnedKey      string
	StateDirectory string
}

type agent struct {
	config    config
	client    *http.Client
	publicKey ed25519.PublicKey
	logger    io.Writer
	now       func() time.Time
}

type apiError struct {
	category string
}

func (e apiError) Error() string { return e.category }

func newAgent(cfg config, logger io.Writer) (*agent, error) {
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, apiError{category: "invalid_api_url"}
	}
	if cfg.NodeID <= 0 || cfg.Credential == "" {
		return nil, apiError{category: "invalid_agent_config"}
	}
	key, err := base64.StdEncoding.DecodeString(cfg.PinnedKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != cfg.PinnedKey {
		return nil, apiError{category: "invalid_pinned_key"}
	}
	if cfg.StateDirectory == "" {
		return nil, apiError{category: "invalid_agent_config"}
	}
	cfg.BaseURL = strings.TrimRight(base.String(), "/")
	return &agent{
		config:    cfg,
		client:    &http.Client{Timeout: 15 * time.Second},
		publicKey: ed25519.PublicKey(key),
		logger:    logger,
		now:       time.Now,
	}, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid URL")
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		local = true
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("HTTPS required")
	}
	return u, nil
}

func (a *agent) run(ctx context.Context) error {
	var snapshot nodeprotocol.Snapshot
	if err := a.getJSON(ctx, "/v1/node/config", &snapshot); err != nil {
		return a.fail(a.config.NodeID, 0, "", err)
	}
	if snapshot.NodeID != a.config.NodeID {
		return a.fail(snapshot.NodeID, snapshot.Version, nodeprotocol.SnapshotDigest(snapshot), apiError{category: "snapshot_node_mismatch"})
	}
	if err := nodeprotocol.ValidateSnapshot(snapshot); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, nodeprotocol.SnapshotDigest(snapshot), apiError{category: "snapshot_invalid"})
	}
	digest := nodeprotocol.SnapshotDigest(snapshot)

	var approvalResponse struct {
		Approval nodeprotocol.Approval `json:"approval"`
		Applied  bool                  `json:"applied"`
	}
	if err := a.getJSON(ctx, "/v1/node/config/approval", &approvalResponse); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, err)
	}
	approval := approvalResponse.Approval
	if approvalResponse.Applied {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, apiError{category: "unexpected_applied_state"})
	}
	if err := nodeprotocol.VerifyApproval(a.publicKey, approval, snapshot.NodeID, snapshot.Version, digest, a.now()); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, apiError{category: err.Error()})
	}
	if err := a.rejectLocalReplay(approval.Nonce); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, err)
	}

	requestBody, err := json.Marshal(map[string]nodeprotocol.Approval{"approval": approval})
	if err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, apiError{category: "request_encode_failed"})
	}
	var result struct {
		Verified         bool  `json:"verified"`
		NodeID           int64 `json:"node_id"`
		CandidateVersion int64 `json:"candidate_version"`
		Applied          bool  `json:"applied"`
	}
	if err := a.requestJSON(ctx, http.MethodPost, "/v1/node/config/approval/verify", bytes.NewReader(requestBody), &result); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, err)
	}
	if !result.Verified || result.Applied || result.NodeID != snapshot.NodeID || result.CandidateVersion != snapshot.Version {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, apiError{category: "verification_response_mismatch"})
	}
	if err := a.persistConsumedNonce(approval.Nonce, approval.ExpiresAt); err != nil {
		return a.fail(snapshot.NodeID, snapshot.Version, digest, apiError{category: "nonce_state_write_failed"})
	}
	a.log(snapshot.NodeID, snapshot.Version, digest, "approval_verified_read_only")
	return nil
}

func (a *agent) fail(nodeID, version int64, digest string, err error) error {
	a.log(nodeID, version, digest, errorCategory(err))
	return err
}

func (a *agent) getJSON(ctx context.Context, path string, dst any) error {
	return a.requestJSON(ctx, http.MethodGet, path, nil, dst)
}

func (a *agent) requestJSON(ctx context.Context, method, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, a.config.BaseURL+path, body)
	if err != nil {
		return apiError{category: "request_build_failed"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.config.Credential)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(req)
	if err != nil {
		return apiError{category: "control_plane_unreachable"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return apiError{category: statusCategory(response.StatusCode)}
	}
	if dst == nil {
		return nil
	}
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(responseBytes) > 2<<20 {
		return apiError{category: "response_too_large_or_unreadable"}
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return apiError{category: "response_invalid"}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return apiError{category: "response_trailing_data"}
	}
	return nil
}

func statusCategory(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "node_credential_rejected"
	case http.StatusNotFound:
		return "approval_unavailable"
	case http.StatusConflict:
		return "approval_rejected_or_replayed"
	case http.StatusUnprocessableEntity:
		return "snapshot_rejected"
	default:
		return "control_plane_request_failed"
	}
}

func (a *agent) rejectLocalReplay(nonce string) error {
	name := a.noncePath(nonce)
	if _, err := os.Stat(name); err == nil {
		return apiError{category: "approval_replayed_locally"}
	} else if !errors.Is(err, os.ErrNotExist) {
		return apiError{category: "nonce_state_unavailable"}
	}
	return nil
}

func (a *agent) persistConsumedNonce(nonce string, expiresAt time.Time) error {
	if err := os.MkdirAll(a.config.StateDirectory, 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.noncePath(nonce), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(file, "%s\n", expiresAt.UTC().Format(time.RFC3339Nano))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (a *agent) noncePath(nonce string) string {
	hash := sha256.Sum256([]byte(nonce))
	return filepath.Join(a.config.StateDirectory, fmt.Sprintf("nonce-%x.seen", hash[:]))
}

func (a *agent) log(nodeID, version int64, digest, category string) {
	if a.logger == nil {
		return
	}
	_ = json.NewEncoder(a.logger).Encode(map[string]any{
		"node_id":  nodeID,
		"version":  version,
		"digest":   digest,
		"category": category,
	})
}
