package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	HTTPListen  string
	SOCKSListen string
	GoogleIP    string
	FrontDomain string
	ScriptIDs   []string
	AuthKey     string
	LogLevel    string
	H2Conns     int

	WorkerURL       string
	TCPTunnelHosts  string
	HTTPTunnelHosts string
	BypassSS        bool
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
	flag.StringVar(&cfg.HTTPListen, "http", "0.0.0.0:8080", "listen address")
	flag.StringVar(&cfg.SOCKSListen, "socks", "", "SOCKS listen address (e.g. 0.0.0.0:1080)")
	flag.StringVar(&cfg.GoogleIP, "google-ip", "216.239.38.120", "Google frontend IP")
	flag.StringVar(&cfg.FrontDomain, "front", "www.google.com", "TLS SNI")
	flag.StringVar(&cfg.AuthKey, "auth-key", "", "shared secret (required)")
	flag.StringVar(&cfg.LogLevel, "log", "info", "log level")
	flag.IntVar(&cfg.H2Conns, "h2-conns", 1, "parallel H2 connections")
	flag.StringVar(&cfg.WorkerURL, "worker-url", "", "Cloudflare Worker URL")
	flag.StringVar(&cfg.TCPTunnelHosts, "tcp-tunnel-hosts", "", "TCP-tunneled hosts (IPs, CIDR, suffixes)")
	flag.StringVar(&cfg.HTTPTunnelHosts, "http-tunnel-hosts", "", "HTTP-tunneled host suffixes")
	flag.BoolVar(&cfg.BypassSS, "bypass-ss", false, "bypass Google SafeSearch")

	flag.Func("script-id", "Apps Script Deployment ID, repeat for load balancing (required)",
		func(v string) error {
			v = strings.TrimSpace(v)
			if v != "" {
				cfg.ScriptIDs = append(cfg.ScriptIDs, v)
			}
			return nil
		})

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE: %s --auth-key <secret> --script-id <id> [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
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
