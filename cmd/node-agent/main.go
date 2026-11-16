package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.BaseURL, "api", os.Getenv("API_BASE_URL"), "control-plane base URL (remote URLs must use HTTPS)")
	flag.Int64Var(&cfg.NodeID, "node-id", envInt64("NODE_ID"), "this node's control-plane ID")
	flag.StringVar(&cfg.PinnedKey, "approval-public-key", os.Getenv("APPROVAL_PUBLIC_KEY"), "pinned Ed25519 public key in standard base64")
	flag.StringVar(&cfg.StateDirectory, "state-dir", os.Getenv("AGENT_STATE_DIR"), "local directory for consumed-nonce markers")
	flag.StringVar(&cfg.PrivateKeyFile, "private-key-file", os.Getenv("WG_PRIVATE_KEY_FILE"), "local WireGuard private-key file (0600 or 0400)")
	flag.StringVar(&cfg.ConfigFile, "config-file", envOr("WG_CONFIG_FILE", "/etc/wireguard/wg-lab.conf"), "managed config file for the dedicated wg-lab interface")
	flag.StringVar(&cfg.InterfaceName, "interface", envOr("WG_INTERFACE", "wg-lab"), "dedicated test interface; only wg-lab is allowed")
	flag.BoolVar(&cfg.Apply, "apply", false, "apply the approved configuration to wg-lab; default is validation and diff only")
	flag.Parse()
	cfg.Credential = os.Getenv("NODE_CREDENTIAL")

	a, err := newAgent(cfg, os.Stdout)
	if err != nil {
		logEvent(os.Stdout, cfg.NodeID, 0, "", errorCategory(err))
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := a.run(ctx); err != nil {
		os.Exit(1)
	}
}

func envInt64(name string) int64 {
	value, _ := strconv.ParseInt(os.Getenv(name), 10, 64)
	return value
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func errorCategory(err error) string {
	var categorized apiError
	if errors.As(err, &categorized) {
		return categorized.category
	}
	return "agent_failed"
}

func logEvent(dst *os.File, nodeID, version int64, digest, category string) {
	_ = json.NewEncoder(dst).Encode(map[string]any{
		"node_id":  nodeID,
		"version":  version,
		"digest":   digest,
		"category": category,
	})
}
