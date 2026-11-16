package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func plannerTestKey(value byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = value
	}
	return base64.StdEncoding.EncodeToString(key)
}

func plannerTestSnapshot(version int64, cidr, gateway string, devices ...nodeConfigDevice) nodeConfigSnapshot {
	return nodeConfigSnapshot{
		NodeID: 7, Version: version, TunnelCIDR: cidr, GatewayAddress: gateway, Devices: devices,
	}
}

func plannerTestPeer(id int64, keyByte byte, platform, address string) nodeConfigDevice {
	return nodeConfigDevice{
		DeviceID: id, PublicKey: plannerTestKey(keyByte), Platform: platform, TunnelAddress: address,
	}
}

func TestWireGuardDryRunGoldenPeerDelta(t *testing.T) {
	confirmed := plannerTestSnapshot(4, "10.70.0.0/29", "10.70.0.1",
		plannerTestPeer(1, 1, "windows", "10.70.0.2"),
		plannerTestPeer(3, 3, "ios", "10.70.0.4"),
	)
	candidate := plannerTestSnapshot(5, "10.70.0.0/29", "10.70.0.1",
		plannerTestPeer(1, 9, "windows", "10.70.0.3"),
		plannerTestPeer(2, 2, "android", "10.70.0.5"),
	)
	plan, validationErrors := planWireGuardDryRun(confirmed, candidate, nil)
	if len(validationErrors) != 0 {
		t.Fatalf("有效快照被拒绝：%v", validationErrors)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("编码 dry-run golden 失败：%v", err)
	}
	want := `{"node_id":7,"confirmed_version":4,"candidate_version":5,"previous_cidr":"10.70.0.0/29","candidate_cidr":"10.70.0.0/29","previous_gateway":"10.70.0.1","candidate_gateway":"10.70.0.1","network_changed":false,"added":[{"device_id":2,"to_address":"10.70.0.5","to_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","to_platform":"android"}],"changed":[{"device_id":1,"from_address":"10.70.0.2","to_address":"10.70.0.3","from_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","to_public_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","from_platform":"windows","to_platform":"windows"}],"removed":[{"device_id":3,"from_address":"10.70.0.4","from_public_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","from_platform":"ios"}]}`
	if string(encoded) != want {
		t.Fatalf("peer delta 与 golden 不一致\nwant: %s\n got: %s", want, encoded)
	}
	if strings.Contains(string(encoded), "private_key") {
		t.Fatal("dry-run 差异不应包含私钥字段")
	}
}

func TestWireGuardDryRunGoldenAddressPoolChange(t *testing.T) {
	confirmed := plannerTestSnapshot(8, "10.71.0.0/29", "10.71.0.1",
		plannerTestPeer(11, 11, "macos", "10.71.0.2"),
	)
	candidate := plannerTestSnapshot(9, "10.72.0.0/29", "10.72.0.1",
		plannerTestPeer(11, 11, "macos", "10.72.0.2"),
	)
	plan, validationErrors := planWireGuardDryRun(confirmed, candidate, nil)
	if len(validationErrors) != 0 {
		t.Fatalf("网段变更快照被拒绝：%v", validationErrors)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("编码地址池 dry-run 失败：%v", err)
	}
	want := `{"node_id":7,"confirmed_version":8,"candidate_version":9,"previous_cidr":"10.71.0.0/29","candidate_cidr":"10.72.0.0/29","previous_gateway":"10.71.0.1","candidate_gateway":"10.72.0.1","network_changed":true,"added":[],"changed":[{"device_id":11,"from_address":"10.71.0.2","to_address":"10.72.0.2","from_public_key":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=","to_public_key":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=","from_platform":"macos","to_platform":"macos"}],"removed":[]}`
	if string(encoded) != want {
		t.Fatalf("地址池变更与 golden 不一致\nwant: %s\n got: %s", want, encoded)
	}
}

func TestWireGuardDryRunIsIdempotentAndRejectsInvalidSnapshots(t *testing.T) {
	valid := plannerTestSnapshot(3, "10.73.0.0/29", "10.73.0.1",
		plannerTestPeer(1, 1, "windows", "10.73.0.2"),
	)
	first, errs := planWireGuardDryRun(valid, valid, nil)
	if len(errs) != 0 {
		t.Fatalf("同一版本快照首次规划失败：%v", errs)
	}
	second, errs := planWireGuardDryRun(valid, valid, nil)
	if len(errs) != 0 {
		t.Fatalf("同一版本快照重复规划失败：%v", errs)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("相同版本重复规划结果应稳定：%s != %s", firstJSON, secondJSON)
	}
	if len(first.Added)+len(first.Changed)+len(first.Removed) != 0 {
		t.Fatalf("同一快照不应产生 peer 差异：%s", firstJSON)
	}

	tests := []struct {
		name      string
		candidate nodeConfigSnapshot
		revoked   map[int64]bool
		wantError string
	}{
		{
			name: "older version",
			candidate: plannerTestSnapshot(2, "10.73.0.0/29", "10.73.0.1",
				plannerTestPeer(1, 1, "windows", "10.73.0.2")),
			wantError: "candidate_version_older_than_confirmed",
		},
		{
			name: "gateway address used by peer",
			candidate: plannerTestSnapshot(4, "10.73.0.0/29", "10.73.0.1",
				plannerTestPeer(1, 1, "windows", "10.73.0.1")),
			wantError: "candidate_invalid_tunnel_address:1",
		},
		{
			name: "conflicting peer addresses",
			candidate: plannerTestSnapshot(4, "10.73.0.0/29", "10.73.0.1",
				plannerTestPeer(1, 1, "windows", "10.73.0.2"),
				plannerTestPeer(2, 2, "ios", "10.73.0.2")),
			wantError: "candidate_duplicate_tunnel_address:10.73.0.2:1:2",
		},
		{
			name:      "revoked peer still present",
			candidate: valid,
			revoked:   map[int64]bool{1: true},
			wantError: "candidate_revoked_device_still_present:1",
		},
		{
			name: "same version different peer set",
			candidate: plannerTestSnapshot(3, "10.73.0.0/29", "10.73.0.1",
				plannerTestPeer(2, 2, "ios", "10.73.0.3")),
			wantError: "same_version_snapshot_mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, validationErrors := planWireGuardDryRun(valid, test.candidate, test.revoked)
			if plan != nil {
				t.Fatalf("无效快照不能生成候选差异：%+v", plan)
			}
			if !containsString(validationErrors, test.wantError) {
				t.Fatalf("错误中应包含 %q，实际为 %v", test.wantError, validationErrors)
			}
		})
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
