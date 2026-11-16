package main

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
)

type dryRunPeerChange struct {
	DeviceID      int64  `json:"device_id"`
	FromAddress   string `json:"from_address,omitempty"`
	ToAddress     string `json:"to_address,omitempty"`
	FromPublicKey string `json:"from_public_key,omitempty"`
	ToPublicKey   string `json:"to_public_key,omitempty"`
	FromPlatform  string `json:"from_platform,omitempty"`
	ToPlatform    string `json:"to_platform,omitempty"`
}

type wireGuardDryRun struct {
	NodeID           int64              `json:"node_id"`
	ConfirmedVersion int64              `json:"confirmed_version"`
	CandidateVersion int64              `json:"candidate_version"`
	PreviousCIDR     string             `json:"previous_cidr"`
	CandidateCIDR    string             `json:"candidate_cidr"`
	PreviousGateway  string             `json:"previous_gateway"`
	CandidateGateway string             `json:"candidate_gateway"`
	NetworkChanged   bool               `json:"network_changed"`
	Added            []dryRunPeerChange `json:"added"`
	Changed          []dryRunPeerChange `json:"changed"`
	Removed          []dryRunPeerChange `json:"removed"`
}

type plannerPeer struct {
	deviceID int64
	key      string
	platform string
	address  string
}

// planWireGuardDryRun validates two metadata snapshots and returns a stable
// peer delta. It never renders a WireGuard configuration or handles private keys.
func planWireGuardDryRun(
	confirmed, candidate nodeConfigSnapshot,
	revokedDeviceIDs map[int64]bool,
) (*wireGuardDryRun, []string) {
	errors := make([]string, 0)
	confirmedPeers, confirmedPrefix, confirmedGateway, confirmedErrors := validatePlannerSnapshot(confirmed, false, nil)
	candidatePeers, candidatePrefix, candidateGateway, candidateErrors := validatePlannerSnapshot(candidate, true, revokedDeviceIDs)
	for _, message := range confirmedErrors {
		errors = append(errors, "confirmed_"+message)
	}
	for _, message := range candidateErrors {
		errors = append(errors, "candidate_"+message)
	}
	if confirmed.NodeID != candidate.NodeID {
		errors = append(errors, "node_id_mismatch")
	}
	if candidate.Version < confirmed.Version {
		errors = append(errors, "candidate_version_older_than_confirmed")
	}
	if candidate.Version == confirmed.Version && len(confirmedErrors) == 0 && len(candidateErrors) == 0 && !samePlannerSnapshot(confirmed, candidate) {
		errors = append(errors, "same_version_snapshot_mismatch")
	}
	if len(errors) > 0 {
		sort.Strings(errors)
		return nil, errors
	}

	plan := &wireGuardDryRun{
		NodeID:           candidate.NodeID,
		ConfirmedVersion: confirmed.Version,
		CandidateVersion: candidate.Version,
		PreviousCIDR:     confirmed.TunnelCIDR,
		CandidateCIDR:    candidate.TunnelCIDR,
		PreviousGateway:  confirmed.GatewayAddress,
		CandidateGateway: candidate.GatewayAddress,
		NetworkChanged:   confirmedPrefix != candidatePrefix || confirmedGateway != candidateGateway,
		Added:            make([]dryRunPeerChange, 0),
		Changed:          make([]dryRunPeerChange, 0),
		Removed:          make([]dryRunPeerChange, 0),
	}
	for id, next := range candidatePeers {
		previous, existed := confirmedPeers[id]
		if !existed {
			plan.Added = append(plan.Added, dryRunPeerChange{
				DeviceID: id, ToAddress: next.address, ToPublicKey: next.key, ToPlatform: next.platform,
			})
			continue
		}
		if previous != next {
			plan.Changed = append(plan.Changed, dryRunPeerChange{
				DeviceID:    id,
				FromAddress: previous.address, ToAddress: next.address,
				FromPublicKey: previous.key, ToPublicKey: next.key,
				FromPlatform: previous.platform, ToPlatform: next.platform,
			})
		}
	}
	for id, previous := range confirmedPeers {
		if _, exists := candidatePeers[id]; !exists {
			plan.Removed = append(plan.Removed, dryRunPeerChange{
				DeviceID: id, FromAddress: previous.address, FromPublicKey: previous.key, FromPlatform: previous.platform,
			})
		}
	}
	sort.Slice(plan.Added, func(i, j int) bool { return plan.Added[i].DeviceID < plan.Added[j].DeviceID })
	sort.Slice(plan.Changed, func(i, j int) bool { return plan.Changed[i].DeviceID < plan.Changed[j].DeviceID })
	sort.Slice(plan.Removed, func(i, j int) bool { return plan.Removed[i].DeviceID < plan.Removed[j].DeviceID })
	return plan, nil
}

func validatePlannerSnapshot(
	snapshot nodeConfigSnapshot,
	candidate bool,
	revokedDeviceIDs map[int64]bool,
) (map[int64]plannerPeer, netip.Prefix, netip.Addr, []string) {
	errors := make([]string, 0)
	peers := make(map[int64]plannerPeer, len(snapshot.Devices))
	if snapshot.NodeID <= 0 {
		errors = append(errors, "invalid_node_id")
	}
	if snapshot.Version < 0 {
		errors = append(errors, "invalid_version")
	}
	prefix, _, err := parseTunnelPrefix(snapshot.TunnelCIDR)
	if err != nil {
		errors = append(errors, "invalid_ipv4_cidr")
		return peers, netip.Prefix{}, netip.Addr{}, errors
	}
	if prefix.String() != snapshot.TunnelCIDR {
		errors = append(errors, "noncanonical_ipv4_cidr")
	}
	gateway := prefixAddress(prefix, 1)
	providedGateway, gatewayErr := netip.ParseAddr(snapshot.GatewayAddress)
	if gatewayErr != nil || providedGateway != gateway {
		errors = append(errors, "invalid_gateway_address")
	}
	addressCount := uint64(1) << (32 - prefix.Bits())
	broadcast := prefixAddress(prefix, addressCount-1)
	keys := make(map[string]int64, len(snapshot.Devices))
	addresses := make(map[netip.Addr]int64, len(snapshot.Devices))
	for _, item := range snapshot.Devices {
		if item.DeviceID <= 0 {
			errors = append(errors, "invalid_device_id")
			continue
		}
		if _, exists := peers[item.DeviceID]; exists {
			errors = append(errors, fmt.Sprintf("duplicate_device_id:%d", item.DeviceID))
			continue
		}
		if candidate && (item.Revoked || revokedDeviceIDs[item.DeviceID]) {
			errors = append(errors, fmt.Sprintf("revoked_device_still_present:%d", item.DeviceID))
		}
		keyBytes, keyErr := base64.StdEncoding.DecodeString(item.PublicKey)
		if keyErr != nil || len(keyBytes) != 32 || base64.StdEncoding.EncodeToString(keyBytes) != item.PublicKey {
			errors = append(errors, fmt.Sprintf("invalid_public_key:%d", item.DeviceID))
		}
		if previousID, exists := keys[item.PublicKey]; item.PublicKey != "" && exists {
			errors = append(errors, fmt.Sprintf("duplicate_public_key:%d:%d", previousID, item.DeviceID))
		} else if item.PublicKey != "" {
			keys[item.PublicKey] = item.DeviceID
		}
		switch item.Platform {
		case "android", "ios", "windows", "macos":
		default:
			errors = append(errors, fmt.Sprintf("invalid_platform:%d", item.DeviceID))
		}
		address, addressErr := netip.ParseAddr(item.TunnelAddress)
		if addressErr != nil || !address.Is4() || !prefix.Contains(address) || address == prefix.Masked().Addr() || address == gateway || address == broadcast {
			errors = append(errors, fmt.Sprintf("invalid_tunnel_address:%d", item.DeviceID))
		} else if previousID, exists := addresses[address]; exists {
			errors = append(errors, fmt.Sprintf("duplicate_tunnel_address:%s:%d:%d", address, previousID, item.DeviceID))
		} else {
			addresses[address] = item.DeviceID
		}
		peers[item.DeviceID] = plannerPeer{
			deviceID: item.DeviceID,
			key:      item.PublicKey,
			platform: item.Platform,
			address:  item.TunnelAddress,
		}
	}
	sort.Strings(errors)
	return peers, prefix, gateway, errors
}

func samePlannerSnapshot(left, right nodeConfigSnapshot) bool {
	if left.NodeID != right.NodeID || left.Version != right.Version ||
		left.TunnelCIDR != right.TunnelCIDR || left.GatewayAddress != right.GatewayAddress ||
		len(left.Devices) != len(right.Devices) {
		return false
	}
	leftPeers, _, _, leftErrors := validatePlannerSnapshot(left, false, nil)
	rightPeers, _, _, rightErrors := validatePlannerSnapshot(right, false, nil)
	if len(leftErrors) != 0 || len(rightErrors) != 0 || len(leftPeers) != len(rightPeers) {
		return false
	}
	for id, peer := range leftPeers {
		if rightPeers[id] != peer {
			return false
		}
	}
	return true
}
