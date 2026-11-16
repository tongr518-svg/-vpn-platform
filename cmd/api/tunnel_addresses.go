package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

var errTunnelAddressPoolExhausted = errors.New("tunnel address pool exhausted")

// parseTunnelPrefix accepts canonical IPv4 networks from /8 through /30.
// Network, gateway (.1), and broadcast addresses are reserved.
func parseTunnelPrefix(raw string) (netip.Prefix, uint64, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return netip.Prefix{}, 0, fmt.Errorf("invalid IPv4 tunnel CIDR")
	}
	prefix = prefix.Masked()
	hostBits := 32 - prefix.Bits()
	addressCount := uint64(1) << hostBits
	return prefix, addressCount - 3, nil
}

func prefixAddress(prefix netip.Prefix, offset uint64) netip.Addr {
	base := prefix.Masked().Addr().As4()
	value := uint64(base[0])<<24 | uint64(base[1])<<16 | uint64(base[2])<<8 | uint64(base[3])
	value += offset
	return netip.AddrFrom4([4]byte{
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	})
}

func allocateTunnelAddress(
	tx pgx.Tx,
	ctx context.Context,
	nodeID, deviceID int64,
	prefix netip.Prefix,
) (netip.Addr, error) {
	// A node row lock serializes allocators for this pool. Scan only occupied
	// addresses, then choose the first usable host from the low end of the pool.
	rows, err := tx.Query(ctx, `
		SELECT host(address)
		FROM node_tunnel_addresses
		WHERE node_id = $1
		ORDER BY address`, nodeID)
	if err != nil {
		return netip.Addr{}, err
	}
	occupied := make(map[netip.Addr]struct{})
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		address, err := netip.ParseAddr(raw)
		if err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		occupied[address] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return netip.Addr{}, err
	}
	rows.Close()

	_, usableCount, err := parseTunnelPrefix(prefix.String())
	if err != nil {
		return netip.Addr{}, err
	}
	for offset := uint64(2); offset < usableCount+2; offset++ {
		candidate := prefixAddress(prefix, offset)
		if _, found := occupied[candidate]; found {
			continue
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO node_tunnel_addresses (node_id, device_id, address, state)
			 VALUES ($1, $2, $3::inet, 'assigned')`,
			nodeID, deviceID, candidate.String(),
		)
		if err != nil {
			return netip.Addr{}, err
		}
		return candidate, nil
	}
	return netip.Addr{}, errTunnelAddressPoolExhausted
}

func markTunnelAddressReleasing(ctx context.Context, tx pgx.Tx, nodeID, deviceID, version int64) error {
	_, err := tx.Exec(ctx,
		`UPDATE node_tunnel_addresses
		 SET state = 'releasing', release_version = $3
		 WHERE node_id = $1 AND device_id = $2 AND state = 'assigned'`,
		nodeID, deviceID, version,
	)
	return err
}

func parseTunnelPrefixForCapacity(raw string, capacity int) (netip.Prefix, error) {
	prefix, usable, err := parseTunnelPrefix(raw)
	if err != nil || uint64(capacity) > usable {
		return netip.Prefix{}, fmt.Errorf("tunnel subnet has fewer usable addresses than node capacity")
	}
	return prefix, nil
}
