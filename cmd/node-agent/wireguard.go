package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"vpn-platform/internal/nodeprotocol"
)

const (
	testInterfaceName   = "wg-lab"
	rollbackConfigName  = "rollback.conf"
	rollbackManagedName = "managed-config.previous"
	applyJournalName    = "apply-journal.json"
	appliedStateName    = "applied-state.json"
)

type wireGuardExecutor interface {
	ShowConfig(context.Context, string) ([]byte, error)
	SetConfig(context.Context, string, string) error
}

type commandWireGuardExecutor struct{}

func (commandWireGuardExecutor) ShowConfig(ctx context.Context, iface string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, "wg", "showconf", iface).Output()
	if err != nil {
		return nil, errors.New("wg_showconf_failed")
	}
	return output, nil
}

func (commandWireGuardExecutor) SetConfig(ctx context.Context, iface, configPath string) error {
	cmd := exec.CommandContext(ctx, "wg", "setconf", iface, configPath)
	if err := cmd.Run(); err != nil {
		return errors.New("wg_setconf_failed")
	}
	return nil
}

type applyJournal struct {
	NodeID           int64                 `json:"node_id"`
	Version          int64                 `json:"version"`
	Digest           string                `json:"digest"`
	Approval         nodeprotocol.Approval `json:"approval"`
	Phase            string                `json:"phase"`
	HadManagedConfig bool                  `json:"had_managed_config"`
}

type appliedState struct {
	NodeID  int64  `json:"node_id"`
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

type configDiff struct {
	Added   int `json:"added_peers"`
	Changed int `json:"changed_peers"`
	Removed int `json:"removed_peers"`
}

type peerConfig struct {
	PublicKey  string
	AllowedIPs string
}

func readPrivateKey(name string) (string, error) {
	if name == "" || !filepath.IsAbs(name) {
		return "", apiError{category: "private_key_file_required"}
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS == "linux" && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0)) {
		return "", apiError{category: "private_key_file_permissions_invalid"}
	}
	contents, err := os.ReadFile(name)
	if err != nil {
		return "", apiError{category: "private_key_file_unreadable"}
	}
	encoded := strings.TrimSpace(string(contents))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return "", apiError{category: "private_key_file_invalid"}
	}
	return encoded, nil
}

func renderWireGuardConfig(snapshot nodeprotocol.Snapshot, privateKey string) ([]byte, error) {
	if err := nodeprotocol.ValidateSnapshot(snapshot); err != nil {
		return nil, apiError{category: "snapshot_invalid"}
	}
	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != privateKey {
		return nil, apiError{category: "private_key_invalid"}
	}
	var out strings.Builder
	out.WriteString("[Interface]\nPrivateKey = ")
	out.WriteString(privateKey)
	out.WriteString("\n")
	for _, device := range snapshot.Devices {
		out.WriteString("\n[Peer]\nPublicKey = ")
		out.WriteString(device.PublicKey)
		out.WriteString("\nAllowedIPs = ")
		out.WriteString(device.TunnelAddress)
		out.WriteString("/32\n")
	}
	config := []byte(out.String())
	if _, err := parseManagedConfig(config); err != nil {
		return nil, apiError{category: "candidate_config_invalid"}
	}
	return config, nil
}

func parseManagedConfig(contents []byte) (map[string]peerConfig, error) {
	peers := make(map[string]peerConfig)
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	section := ""
	interfaceSeen := false
	interfaceKeySeen := false
	var current *peerConfig
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				return nil, errors.New("incomplete peer")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			switch section {
			case "Interface":
				if interfaceSeen || current != nil {
					return nil, errors.New("invalid interface section")
				}
				interfaceSeen = true
			case "Peer":
				if !interfaceSeen {
					return nil, errors.New("peer before interface")
				}
				current = &peerConfig{}
			default:
				return nil, errors.New("unknown section")
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, errors.New("invalid config line")
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch section {
		case "Interface":
			if key != "PrivateKey" || interfaceKeySeen {
				return nil, errors.New("unsupported interface setting")
			}
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
				return nil, errors.New("invalid interface key")
			}
			interfaceKeySeen = true
		case "Peer":
			if current == nil {
				return nil, errors.New("peer section missing")
			}
			switch key {
			case "PublicKey":
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != value || current.PublicKey != "" {
					return nil, errors.New("invalid peer key")
				}
				current.PublicKey = value
			case "AllowedIPs":
				prefix, err := netip.ParsePrefix(value)
				if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != value || current.AllowedIPs != "" {
					return nil, errors.New("invalid peer address")
				}
				current.AllowedIPs = value
			default:
				return nil, errors.New("unsupported peer setting")
			}
		default:
			return nil, errors.New("setting outside section")
		}
		if section == "Peer" && current.PublicKey != "" && current.AllowedIPs != "" {
			if _, exists := peers[current.PublicKey]; exists {
				return nil, errors.New("duplicate peer")
			}
			peers[current.PublicKey] = *current
			current = nil
		}
	}
	if err := scanner.Err(); err != nil || !interfaceSeen || !interfaceKeySeen || current != nil {
		return nil, errors.New("incomplete config")
	}
	return peers, nil
}

func readManagedConfig(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("managed config permissions invalid")
	}
	contents, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	if _, err := parseManagedConfig(contents); err != nil {
		return nil, err
	}
	return contents, nil
}

func compareWireGuardConfigs(previous, candidate []byte) (configDiff, error) {
	oldPeers := map[string]peerConfig{}
	var err error
	if len(previous) != 0 {
		oldPeers, err = parseManagedConfig(previous)
		if err != nil {
			return configDiff{}, err
		}
	}
	newPeers, err := parseManagedConfig(candidate)
	if err != nil {
		return configDiff{}, err
	}
	var diff configDiff
	for key, next := range newPeers {
		old, exists := oldPeers[key]
		if !exists {
			diff.Added++
		} else if old != next {
			diff.Changed++
		}
	}
	for key := range oldPeers {
		if _, exists := newPeers[key]; !exists {
			diff.Removed++
		}
	}
	return diff, nil
}

func atomicWrite(name string, contents []byte, mode os.FileMode) error {
	return atomicWriteValidated(name, contents, mode, nil)
}

func atomicWriteConfig(name string, contents []byte) error {
	return atomicWriteValidated(name, contents, 0600, func(candidate []byte) error {
		_, err := parseManagedConfig(candidate)
		return err
	})
}

func atomicWriteValidated(name string, contents []byte, mode os.FileMode, validate func([]byte) error) error {
	dir := filepath.Dir(name)
	file, err := os.CreateTemp(dir, ".agent-tmp-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if validate != nil {
		written, err := os.ReadFile(temp)
		if err != nil {
			return err
		}
		if err := validate(written); err != nil {
			return err
		}
	}
	if err := os.Rename(temp, name); err != nil {
		return err
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func ensurePrivateDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || (runtime.GOOS == "linux" && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0700 != 0700)) {
		return errors.New("directory permissions invalid")
	}
	return nil
}

func (a *agent) journalPath() string { return filepath.Join(a.config.StateDirectory, applyJournalName) }

func (a *agent) writeJournal(journal applyJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicWrite(a.journalPath(), data, 0600)
}

func (a *agent) readJournal() (applyJournal, error) {
	var journal applyJournal
	if err := a.validateStateDirectoryIfPresent(); err != nil {
		return journal, err
	}
	if err := readSecureJSON(a.journalPath(), &journal); err != nil {
		return journal, err
	}
	if journal.NodeID != a.config.NodeID || journal.Version < 0 || journal.Digest == "" {
		return journal, errors.New("invalid journal")
	}
	return journal, nil
}

func (a *agent) writeAppliedState(state appliedState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(a.config.StateDirectory, appliedStateName), data, 0600)
}

func (a *agent) readAppliedState() (appliedState, error) {
	var state appliedState
	if err := a.validateStateDirectoryIfPresent(); err != nil {
		return state, err
	}
	err := readSecureJSON(filepath.Join(a.config.StateDirectory, appliedStateName), &state)
	return state, err
}

func (a *agent) validateStateDirectoryIfPresent() error {
	info, err := os.Lstat(a.config.StateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || (runtime.GOOS == "linux" && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0700 != 0700)) {
		return errors.New("state directory permissions invalid")
	}
	return nil
}

func readSecureJSON(name string, dst any) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS == "linux" && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0)) {
		return errors.New("state file permissions invalid")
	}
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("state file trailing data")
	}
	return nil
}

func (a *agent) clearJournal() error {
	if err := os.Remove(a.journalPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Join(a.config.StateDirectory, rollbackConfigName))
	_ = os.Remove(filepath.Join(a.config.StateDirectory, rollbackManagedName))
	return nil
}

func (a *agent) applyApproved(ctx context.Context, snapshot nodeprotocol.Snapshot, approval nodeprotocol.Approval, digest string, candidate []byte) error {
	if a.platform != "linux" {
		return apiError{category: "apply_requires_linux"}
	}
	if err := os.MkdirAll(a.config.StateDirectory, 0700); err != nil || ensurePrivateDirectory(a.config.StateDirectory) != nil {
		return apiError{category: "local_state_permissions_invalid"}
	}
	previous, err := a.executor.ShowConfig(ctx, testInterfaceName)
	if err != nil {
		return apiError{category: "test_interface_unavailable"}
	}
	managedPrevious, err := os.ReadFile(a.config.ConfigFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return apiError{category: "current_config_unavailable"}
	}
	hadManaged := err == nil
	if err := atomicWrite(filepath.Join(a.config.StateDirectory, rollbackConfigName), previous, 0600); err != nil {
		return apiError{category: "rollback_state_write_failed"}
	}
	if err := atomicWrite(a.config.ConfigFile+".previous", previous, 0600); err != nil {
		return apiError{category: "rollback_state_write_failed"}
	}
	if hadManaged {
		if err := atomicWrite(filepath.Join(a.config.StateDirectory, rollbackManagedName), managedPrevious, 0600); err != nil {
			return apiError{category: "rollback_state_write_failed"}
		}
	} else {
		_ = os.Remove(filepath.Join(a.config.StateDirectory, rollbackManagedName))
	}
	journal := applyJournal{NodeID: snapshot.NodeID, Version: snapshot.Version, Digest: digest, Approval: approval, Phase: "applying", HadManagedConfig: hadManaged}
	if err := a.writeJournal(journal); err != nil {
		return apiError{category: "local_state_write_failed"}
	}
	if err := atomicWriteConfig(a.config.ConfigFile, candidate); err != nil {
		if a.rollbackApply(ctx, journal) != nil {
			return apiError{category: "apply_rollback_failed"}
		}
		_ = a.clearJournal()
		return apiError{category: "candidate_config_write_failed"}
	}
	if err := a.executor.SetConfig(ctx, testInterfaceName, a.config.ConfigFile); err != nil {
		if a.rollbackApply(ctx, journal) != nil {
			return apiError{category: "apply_rollback_failed"}
		}
		_ = a.clearJournal()
		return apiError{category: "apply_failed_rolled_back"}
	}
	journal.Phase = "applied"
	if err := a.writeJournal(journal); err != nil {
		// The applying journal remains durable. Recovery restores the previous
		// config rather than treating this crash window as a successful apply.
		return apiError{category: "apply_state_write_failed"}
	}
	return a.finishApplied(ctx, journal)
}

func (a *agent) finishApplied(ctx context.Context, journal applyJournal) error {
	if journal.Phase == "applied" {
		requestBody, err := json.Marshal(map[string]any{"approval": journal.Approval, "applied": true})
		if err != nil {
			return apiError{category: "request_encode_failed"}
		}
		var result struct {
			Verified         bool  `json:"verified"`
			NodeID           int64 `json:"node_id"`
			CandidateVersion int64 `json:"candidate_version"`
			Applied          bool  `json:"applied"`
		}
		if err := a.requestJSON(ctx, http.MethodPost, "/v1/node/config/approval/verify", bytes.NewReader(requestBody), &result); err != nil {
			if errorCategory(err) == "approval_rejected_or_replayed" {
				if rollbackErr := a.rollbackApply(ctx, journal); rollbackErr != nil {
					return apiError{category: "apply_rollback_failed"}
				}
				if clearErr := a.clearJournal(); clearErr != nil {
					return apiError{category: "local_state_cleanup_failed"}
				}
			}
			return err
		}
		if !result.Verified || !result.Applied || result.NodeID != journal.NodeID || result.CandidateVersion != journal.Version {
			return apiError{category: "application_confirmation_mismatch"}
		}
		journal.Phase = "consumed"
		if err := a.writeJournal(journal); err != nil {
			return apiError{category: "apply_state_write_failed"}
		}
	}
	if journal.Phase == "consumed" {
		body, _ := json.Marshal(map[string]int64{"version": journal.Version})
		if err := a.requestJSON(ctx, http.MethodPost, "/v1/node/config/ack", bytes.NewReader(body), nil); err != nil {
			return err
		}
		if err := a.persistConsumedNonce(journal.Approval.Nonce, journal.Approval.ExpiresAt); err != nil && !errors.Is(err, os.ErrExist) {
			return apiError{category: "nonce_state_write_failed"}
		}
		if err := a.writeAppliedState(appliedState{NodeID: journal.NodeID, Version: journal.Version, Digest: journal.Digest}); err != nil {
			return apiError{category: "local_state_write_failed"}
		}
		if err := a.clearJournal(); err != nil {
			return apiError{category: "local_state_cleanup_failed"}
		}
	}
	return nil
}

func (a *agent) recoverApply(ctx context.Context) error {
	if info, statErr := os.Lstat(a.config.StateDirectory); statErr == nil {
		if !info.IsDir() || (runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0) {
			return apiError{category: "local_state_permissions_invalid"}
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return apiError{category: "local_state_unavailable"}
	}
	journal, err := a.readJournal()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return apiError{category: "local_state_unavailable"}
	}
	switch journal.Phase {
	case "applying":
		if err := a.rollbackApply(ctx, journal); err != nil {
			return apiError{category: "apply_recovery_failed"}
		}
		return a.clearJournal()
	case "applied", "consumed":
		if err := nodeprotocol.VerifyApproval(a.publicKey, journal.Approval, journal.NodeID, journal.Version, journal.Digest, journal.Approval.IssuedAt); err != nil {
			return apiError{category: "local_state_invalid"}
		}
		return a.finishApplied(ctx, journal)
	default:
		return apiError{category: "local_state_invalid"}
	}
}

func (a *agent) rollbackApply(ctx context.Context, journal applyJournal) error {
	rollbackPath := filepath.Join(a.config.StateDirectory, rollbackConfigName)
	if _, err := os.Stat(rollbackPath); err != nil {
		return err
	}
	if err := a.executor.SetConfig(ctx, testInterfaceName, rollbackPath); err != nil {
		return err
	}
	if journal.HadManagedConfig {
		previous, err := os.ReadFile(filepath.Join(a.config.StateDirectory, rollbackManagedName))
		if err != nil {
			return err
		}
		return atomicWrite(a.config.ConfigFile, previous, 0600)
	}
	if err := os.Remove(a.config.ConfigFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (a *agent) logDiff(nodeID, version int64, digest string, diff configDiff, category string) {
	if a.logger == nil {
		return
	}
	_ = json.NewEncoder(a.logger).Encode(map[string]any{
		"node_id": nodeID, "version": version, "digest": digest, "category": category,
		"added_peers": diff.Added, "changed_peers": diff.Changed, "removed_peers": diff.Removed,
	})
}
