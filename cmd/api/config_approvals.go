package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/nodeprotocol"
)

const configApprovalLifetime = 10 * time.Minute

type approveNodeConfigRequest struct {
	CandidateVersion int64 `json:"candidate_version"`
}

type nodeConfigApproval = nodeprotocol.Approval

type verifyNodeApprovalRequest struct {
	Approval nodeConfigApproval `json:"approval"`
	Applied  bool               `json:"applied"`
}

type configSigningKeyResponse struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

func deriveConfigSigningKey(secret string) (ed25519.PrivateKey, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("config signing secret must be at least 32 bytes")
	}
	seed := sha256.Sum256([]byte("vpn-platform/config-signing/v1\x00" + secret))
	return ed25519.NewKeyFromSeed(seed[:]), nil
}

func candidateSnapshotDigest(snapshot nodeConfigSnapshot) (string, error) {
	return nodeprotocol.SnapshotDigest(snapshot), nil
}

func approvalMessage(approval nodeConfigApproval) []byte {
	return nodeprotocol.ApprovalMessage(approval)
}

func (a *API) adminApproveNodeConfig(w http.ResponseWriter, r *http.Request) {
	actorID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	nodeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_node_id"})
		return
	}
	var in approveNodeConfigRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.CandidateVersion < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_candidate_version"})
		return
	}
	if len(a.configSigningKey) != ed25519.PrivateKeySize {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config_signing_unavailable"})
		return
	}

	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())

	var desiredVersion int64
	err = tx.QueryRow(r.Context(), `SELECT desired_config_version FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&desiredVersion)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if in.CandidateVersion != desiredVersion {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "candidate_version_mismatch"})
		return
	}

	var status, storedDigest string
	var storedVersion int64
	err = tx.QueryRow(r.Context(),
		`SELECT status, candidate_version, candidate_digest
		 FROM node_config_dry_runs WHERE node_id = $1 FOR UPDATE`, nodeID,
	).Scan(&status, &storedVersion, &storedDigest)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "valid_current_dry_run_required"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if status != "valid" || storedDigest == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "valid_current_dry_run_required"})
		return
	}
	if storedVersion != desiredVersion || in.CandidateVersion != desiredVersion {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "candidate_version_mismatch"})
		return
	}
	currentSnapshot, err := loadNodeConfigSnapshot(r.Context(), tx, nodeID, desiredVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	currentDigest, err := candidateSnapshotDigest(currentSnapshot)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if currentDigest != storedDigest {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "candidate_changed_since_dry_run"})
		return
	}

	var existing nodeConfigApproval
	var existingSignature []byte
	var consumed bool
	err = tx.QueryRow(r.Context(),
		`SELECT id, node_id, candidate_version, candidate_digest, nonce, signature, approved_at, expires_at,
	                consumed_at IS NOT NULL
		 FROM node_config_approvals
		 WHERE node_id = $1 AND candidate_version = $2 AND candidate_digest = $3
		 FOR UPDATE`, nodeID, desiredVersion, storedDigest,
	).Scan(&existing.ID, &existing.NodeID, &existing.CandidateVersion, &existing.CandidateDigest,
		&existing.Nonce, &existingSignature, &existing.IssuedAt, &existing.ExpiresAt, &consumed)
	if err == nil {
		if consumed {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_already_consumed"})
			return
		}
		if existing.ExpiresAt.After(time.Now()) && ed25519.Verify(
			a.configSigningKey.Public().(ed25519.PublicKey), approvalMessage(existing), existingSignature,
		) {
			existing.Signature = base64.StdEncoding.EncodeToString(existingSignature)
			if err := tx.Commit(r.Context()); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"approval": existing, "reused": true, "applied": false})
			return
		}
	} else if err != pgx.ErrNoRows {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	approval := nodeConfigApproval{
		NodeID: nodeID, CandidateVersion: desiredVersion, CandidateDigest: storedDigest,
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes), IssuedAt: issuedAt,
		ExpiresAt: issuedAt.Add(configApprovalLifetime),
	}
	signature := ed25519.Sign(a.configSigningKey, approvalMessage(approval))
	approval.Signature = base64.StdEncoding.EncodeToString(signature)
	if existing.ID > 0 {
		err = tx.QueryRow(r.Context(),
			`UPDATE node_config_approvals
			 SET nonce = $1, signature = $2, approved_by = $3, approved_at = $4, expires_at = $5, consumed_at = NULL
			 WHERE id = $6 RETURNING id`,
			approval.Nonce, signature, actorID, issuedAt, approval.ExpiresAt, existing.ID,
		).Scan(&approval.ID)
	} else {
		err = tx.QueryRow(r.Context(),
			`INSERT INTO node_config_approvals
			 (node_id, candidate_version, candidate_digest, nonce, signature, approved_by, approved_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			nodeID, desiredVersion, storedDigest, approval.Nonce, signature, actorID, issuedAt, approval.ExpiresAt,
		).Scan(&approval.ID)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := insertAudit(r, tx, actorID, "approve_node_config", "node_config_approval", approval.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"approval": approval, "reused": false, "applied": false})
}

func (a *API) nodeConfigSigningKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.nodeIDForRequest(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if len(a.configSigningKey) != ed25519.PrivateKeySize {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config_signing_unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, configSigningKeyResponse{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(a.configSigningKey.Public().(ed25519.PublicKey)),
	})
}

func (a *API) nodeGetConfigApproval(w http.ResponseWriter, r *http.Request) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	tx, err := a.db.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	nodeID, desiredVersion, err := nodeIDForCredential(r.Context(), tx, tokenHash)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	var approval nodeConfigApproval
	var signature []byte
	err = tx.QueryRow(r.Context(),
		`SELECT a.id, a.node_id, a.candidate_version, a.candidate_digest, a.nonce,
		        a.signature, a.approved_at, a.expires_at
		 FROM node_config_approvals a
		 JOIN nodes n ON n.id = a.node_id
		 JOIN node_config_dry_runs d ON d.node_id = a.node_id
		 WHERE a.node_id = $1 AND a.consumed_at IS NULL AND a.expires_at > NOW()
		   AND a.candidate_version = n.desired_config_version
		   AND a.candidate_version = d.candidate_version
		   AND a.candidate_digest = d.candidate_digest AND d.status = 'valid'
		 ORDER BY a.id DESC LIMIT 1`, nodeID,
	).Scan(&approval.ID, &approval.NodeID, &approval.CandidateVersion, &approval.CandidateDigest,
		&approval.Nonce, &signature, &approval.IssuedAt, &approval.ExpiresAt)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no_current_config_approval"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	snapshot, err := loadNodeConfigSnapshot(r.Context(), tx, nodeID, desiredVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	currentDigest, err := candidateSnapshotDigest(snapshot)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if approval.CandidateVersion != desiredVersion || currentDigest != approval.CandidateDigest {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no_current_config_approval"})
		return
	}
	if len(a.configSigningKey) != ed25519.PrivateKeySize ||
		!ed25519.Verify(a.configSigningKey.Public().(ed25519.PublicKey), approvalMessage(approval), signature) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no_current_config_approval"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	approval.Signature = base64.StdEncoding.EncodeToString(signature)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"approval": approval, "applied": false})
}

func (a *API) nodeVerifyConfigApproval(w http.ResponseWriter, r *http.Request) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var in verifyNodeApprovalRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(a.configSigningKey) != ed25519.PrivateKeySize {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config_signing_unavailable"})
		return
	}
	approval := in.Approval
	if !in.Applied {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "configuration_not_applied"})
		return
	}
	if approval.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_approval_id"})
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	defer tx.Rollback(r.Context())
	nodeID, _, err := nodeIDForCredential(r.Context(), tx, tokenHash)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if approval.NodeID != nodeID {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_node_mismatch"})
		return
	}
	var lockedNodeID int64
	if err := tx.QueryRow(r.Context(), `SELECT id FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&lockedNodeID); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(a.configSigningKey.Public().(ed25519.PublicKey), approvalMessage(approval), signature) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invalid_approval_signature"})
		return
	}
	var stored nodeConfigApproval
	var storedSignature []byte
	var consumed, applied bool
	err = tx.QueryRow(r.Context(),
		`SELECT id, node_id, candidate_version, candidate_digest, nonce, signature, approved_at, expires_at,
	                consumed_at IS NOT NULL, applied_at IS NOT NULL
		 FROM node_config_approvals WHERE id = $1 FOR UPDATE`, approval.ID,
	).Scan(&stored.ID, &stored.NodeID, &stored.CandidateVersion, &stored.CandidateDigest, &stored.Nonce,
		&storedSignature, &stored.IssuedAt, &stored.ExpiresAt, &consumed, &applied)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if stored.NodeID != approval.NodeID || stored.CandidateVersion != approval.CandidateVersion ||
		stored.CandidateDigest != approval.CandidateDigest || stored.Nonce != approval.Nonce ||
		!stored.IssuedAt.Equal(approval.IssuedAt) || !stored.ExpiresAt.Equal(approval.ExpiresAt) ||
		!ed25519.Verify(a.configSigningKey.Public().(ed25519.PublicKey), approvalMessage(stored), storedSignature) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_payload_mismatch"})
		return
	}
	if consumed {
		if !applied {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_consumed_without_apply_record"})
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": true, "node_id": nodeID, "candidate_version": stored.CandidateVersion, "applied": true,
		})
		return
	}
	if !stored.ExpiresAt.After(time.Now()) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_expired"})
		return
	}
	var desiredVersion int64
	var storedDigest string
	err = tx.QueryRow(r.Context(),
		`SELECT n.desired_config_version, d.candidate_digest
		 FROM nodes n JOIN node_config_dry_runs d ON d.node_id = n.id
		 WHERE n.id = $1 AND d.status = 'valid'
		 FOR UPDATE OF n, d`, nodeID,
	).Scan(&desiredVersion, &storedDigest)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_candidate_stale"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	currentSnapshot, err := loadNodeConfigSnapshot(r.Context(), tx, nodeID, desiredVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	currentDigest, err := candidateSnapshotDigest(currentSnapshot)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if desiredVersion != stored.CandidateVersion || storedDigest != stored.CandidateDigest || currentDigest != stored.CandidateDigest {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "approval_candidate_stale"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE node_config_approvals
		 SET consumed_at = NOW(), applied_at = NOW()
		 WHERE id = $1 AND consumed_at IS NULL`, approval.ID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true, "node_id": nodeID, "candidate_version": stored.CandidateVersion, "applied": true,
	})
}

func (a *API) nodeIDForRequest(r *http.Request) (int64, bool) {
	tokenHash, ok := nodeCredentialHash(r)
	if !ok {
		return 0, false
	}
	var nodeID int64
	err := a.db.QueryRow(r.Context(),
		`SELECT n.id FROM nodes n JOIN node_credentials c ON c.node_id = n.id
		 WHERE c.token_hash = $1 AND c.revoked_at IS NULL AND n.status IN ('active', 'maintenance')`, tokenHash[:],
	).Scan(&nodeID)
	return nodeID, err == nil
}
