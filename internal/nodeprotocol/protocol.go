// Package nodeprotocol defines the byte-level, language-neutral protocol used
// by the read-only node agent and the control-plane API.
package nodeprotocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ApprovalDomain = "vpn-platform-node-config-approval-v1"
	SnapshotDomain = "vpn-platform-node-config-snapshot-v1"
	MaxApprovalTTL = 10 * time.Minute
)

type Device struct {
	DeviceID      int64     `json:"device_id"`
	PublicKey     string    `json:"public_key"`
	Platform      string    `json:"platform"`
	AssignedAt    time.Time `json:"assigned_at"`
	TunnelAddress string    `json:"tunnel_address"`
	Revoked       bool      `json:"-"`
}

type Snapshot struct {
	NodeID         int64    `json:"node_id"`
	Version        int64    `json:"version"`
	TunnelCIDR     string   `json:"tunnel_cidr"`
	GatewayAddress string   `json:"gateway_address"`
	Devices        []Device `json:"devices"`
}

type Approval struct {
	ID               int64     `json:"approval_id"`
	NodeID           int64     `json:"node_id"`
	CandidateVersion int64     `json:"candidate_version"`
	CandidateDigest  string    `json:"candidate_digest"`
	Nonce            string    `json:"nonce"`
	Signature        string    `json:"signature"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// CanonicalSnapshot returns the v1 canonical byte representation. Fields use
// fixed order, peers sort by device ID, opaque text fields use unpadded base64url,
// and timestamps are UTC RFC3339Nano. This format intentionally avoids JSON
// encoder differences across programming languages.
func CanonicalSnapshot(snapshot Snapshot) []byte {
	var out strings.Builder
	out.WriteString(SnapshotDomain)
	out.WriteByte('\n')
	out.WriteString("node_id=")
	out.WriteString(strconv.FormatInt(snapshot.NodeID, 10))
	out.WriteByte('\n')
	out.WriteString("version=")
	out.WriteString(strconv.FormatInt(snapshot.Version, 10))
	out.WriteByte('\n')
	out.WriteString("tunnel_cidr=")
	out.WriteString(base64.RawURLEncoding.EncodeToString([]byte(snapshot.TunnelCIDR)))
	out.WriteByte('\n')
	out.WriteString("gateway_address=")
	out.WriteString(base64.RawURLEncoding.EncodeToString([]byte(snapshot.GatewayAddress)))
	out.WriteByte('\n')

	devices := append([]Device(nil), snapshot.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].DeviceID < devices[j].DeviceID })
	for _, device := range devices {
		out.WriteString("peer=")
		out.WriteString(strconv.FormatInt(device.DeviceID, 10))
		out.WriteByte('\t')
		out.WriteString(base64.RawURLEncoding.EncodeToString([]byte(device.PublicKey)))
		out.WriteByte('\t')
		out.WriteString(device.Platform)
		out.WriteByte('\t')
		out.WriteString(device.AssignedAt.UTC().Format(time.RFC3339Nano))
		out.WriteByte('\t')
		out.WriteString(device.TunnelAddress)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func SnapshotDigest(snapshot Snapshot) string {
	digest := sha256.Sum256(CanonicalSnapshot(snapshot))
	return hex.EncodeToString(digest[:])
}

func ApprovalMessage(approval Approval) []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%d\n%s\n%d\n%d\n%s",
		ApprovalDomain,
		approval.NodeID,
		approval.CandidateVersion,
		approval.CandidateDigest,
		approval.IssuedAt.UTC().Unix(),
		approval.ExpiresAt.UTC().Unix(),
		approval.Nonce,
	))
}

// VerifyApproval verifies the signed fields against the locally observed node,
// version, and candidate digest. Callers should persist the nonce after the
// server confirms successful one-time consumption.
func VerifyApproval(
	publicKey ed25519.PublicKey,
	approval Approval,
	expectedNodeID, expectedVersion int64,
	expectedDigest string,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize || approval.ID <= 0 {
		return fmt.Errorf("invalid_key_or_approval_id")
	}
	if approval.NodeID != expectedNodeID || expectedNodeID <= 0 {
		return fmt.Errorf("approval_node_mismatch")
	}
	if approval.CandidateVersion != expectedVersion || expectedVersion < 0 {
		return fmt.Errorf("approval_version_mismatch")
	}
	if len(expectedDigest) != sha256.Size*2 || approval.CandidateDigest != expectedDigest || !isLowerHex(expectedDigest) {
		return fmt.Errorf("approval_digest_mismatch")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(approval.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != approval.Nonce {
		return fmt.Errorf("approval_nonce_invalid")
	}
	issuedAt, expiresAt := approval.IssuedAt.UTC(), approval.ExpiresAt.UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || expiresAt.After(issuedAt.Add(MaxApprovalTTL)) || !expiresAt.After(issuedAt) {
		return fmt.Errorf("approval_lifetime_invalid")
	}
	if issuedAt.After(now.UTC().Add(30 * time.Second)) {
		return fmt.Errorf("approval_issued_in_future")
	}
	if !expiresAt.After(now.UTC()) {
		return fmt.Errorf("approval_expired")
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != approval.Signature {
		return fmt.Errorf("approval_signature_encoding_invalid")
	}
	if !ed25519.Verify(publicKey, ApprovalMessage(approval), signature) {
		return fmt.Errorf("approval_signature_invalid")
	}
	return nil
}

func ValidateSnapshot(snapshot Snapshot) error {
	if snapshot.NodeID <= 0 || snapshot.Version < 0 {
		return fmt.Errorf("snapshot_identity_invalid")
	}
	prefix, err := netip.ParsePrefix(snapshot.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return fmt.Errorf("snapshot_cidr_invalid")
	}
	gateway := addIPv4(prefix.Masked().Addr(), 1)
	providedGateway, err := netip.ParseAddr(snapshot.GatewayAddress)
	if err != nil || providedGateway != gateway {
		return fmt.Errorf("snapshot_gateway_invalid")
	}
	broadcast := addIPv4(prefix.Masked().Addr(), (uint64(1)<<uint(32-prefix.Bits()))-1)
	seenIDs := make(map[int64]struct{}, len(snapshot.Devices))
	seenKeys := make(map[string]struct{}, len(snapshot.Devices))
	seenAddresses := make(map[netip.Addr]struct{}, len(snapshot.Devices))
	for _, device := range snapshot.Devices {
		if device.Revoked {
			return fmt.Errorf("snapshot_contains_revoked_peer")
		}
		if device.DeviceID <= 0 || device.AssignedAt.IsZero() {
			return fmt.Errorf("snapshot_peer_identity_invalid")
		}
		if _, exists := seenIDs[device.DeviceID]; exists {
			return fmt.Errorf("snapshot_duplicate_device_id")
		}
		seenIDs[device.DeviceID] = struct{}{}
		key, err := base64.StdEncoding.DecodeString(device.PublicKey)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != device.PublicKey {
			return fmt.Errorf("snapshot_public_key_invalid")
		}
		if _, exists := seenKeys[device.PublicKey]; exists {
			return fmt.Errorf("snapshot_duplicate_public_key")
		}
		seenKeys[device.PublicKey] = struct{}{}
		switch device.Platform {
		case "android", "ios", "windows", "macos":
		default:
			return fmt.Errorf("snapshot_platform_invalid")
		}
		address, err := netip.ParseAddr(device.TunnelAddress)
		if err != nil || !address.Is4() || address.String() != device.TunnelAddress ||
			!prefix.Contains(address) || address == prefix.Masked().Addr() || address == gateway || address == broadcast {
			return fmt.Errorf("snapshot_tunnel_address_invalid")
		}
		if _, exists := seenAddresses[address]; exists {
			return fmt.Errorf("snapshot_duplicate_tunnel_address")
		}
		seenAddresses[address] = struct{}{}
	}
	return nil
}

func addIPv4(base netip.Addr, offset uint64) netip.Addr {
	bytes := base.As4()
	value := uint64(bytes[0])<<24 | uint64(bytes[1])<<16 | uint64(bytes[2])<<8 | uint64(bytes[3])
	value += offset
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func isLowerHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
