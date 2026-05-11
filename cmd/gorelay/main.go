package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	HTTPListen  string   `json:"http_port"`
	SOCKSListen string   `json:"socks5_port"`
	GoogleIP    string   `json:"google_ip"`
	FrontDomain string   `json:"front_domain"`
	ScriptIDs   []string `json:"script_ids"`
	AuthKey     string   `json:"auth_key"`
	LogLevel    string   `json:"log_level"`
	H2Conns     int      `json:"h2_connections_count"`

	WorkerURL       string `json:"worker_url"`
	TCPTunnelHosts  string `json:"tcp_tunnels_host"`
	HTTPTunnelHosts string `json:"http_tunnels_host"`
	BypassSS        bool   `json:"bypass_ss"`
}

const caDir = "./ca"

func main() {
	cfg := parseFlags()

	setupLogger(cfg.LogLevel)

	if len(cfg.ScriptIDs) == 0 || cfg.AuthKey == "" {
		fmt.Fprintln(os.Stderr,
			"--script-id and --auth-key are required.")
		os.Exit(2)
	}
	if strings.Contains(cfg.AuthKey, "CHANGE_ME") {
		fmt.Fprintln(os.Stderr,
			"refuse to start with the placeholder auth key — pick a real secret.")
		os.Exit(2)
	}
	if (cfg.TCPTunnelHosts != "" || cfg.HTTPTunnelHosts != "" || cfg.BypassSS) &&
		cfg.WorkerURL == "" {
		fmt.Fprintln(os.Stderr,
			"--tcp-tunnel-hosts, --http-tunnel-hosts, and --bypass-ss all require --worker-url.")
		os.Exit(2)
	}
	cfg.WorkerURL = normalizeWorkerURL(cfg.WorkerURL)

	if cfg.BypassSS {
		if cfg.HTTPTunnelHosts == "" {
			cfg.HTTPTunnelHosts = "youtube.com"
		} else {
			cfg.HTTPTunnelHosts = "youtube.com," + cfg.HTTPTunnelHosts
		}
	}

	ca, err := loadOrCreateCA(caDir)
	if err != nil {
		slog.Error("CA setup failed", "err", err)
		os.Exit(1)
	}
	slog.Info("CA ready", "dir", caDir, "fingerprint", ca.Fingerprint())

	relay := newRelayClient(cfg)
	defer relay.Close()

	srv := newProxy(cfg, ca, relay)

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		slog.Error("proxy stopped", "err", err)
		os.Exit(1)
	}
}

func parseFlags() *Config {
	cfg := &Config{}
	data, err := os.ReadFile("./config.json")
	if err != nil {
		slog.Error("Error reading file: %v\n", "err", err)
		os.Exit(1)
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		slog.Error("Error parsing JSON: %v\n", "err", err)
		os.Exit(1)
	}
	return cfg
}

func normalizeWorkerURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimRight(u, "/")
	if u == "" {
		return ""
	}
	low := strings.ToLower(u)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return u
	}
	return "https://" + u
}

func setupLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: lvl})))
}
