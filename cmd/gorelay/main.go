package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	HTTPListen  string   `json:"http"`
	SOCKSListen string   `json:"socks"`
	GoogleIP    string   `json:"google_ip"`
	FrontDomain string   `json:"front_domain"`
	ScriptIDs   []string `json:"script_ids"`
	AuthKey     string   `json:"auth_key"`
	LogLevel    string   `json:"log_level"`
	H2Conns     int      `json:"h2_conns"`

	WorkerURL       string `json:"worker_url"`
	TCPTunnelHosts  string `json:"tcp_tunnel_hosts"`
	HTTPTunnelHosts string `json:"http_tunnel_hosts"`
	BypassSS        bool   `json:"bypass_ss"`
}

const (
	caDir             = "./ca"
	defaultConfigPath = "config.json"
)

func main() {
	cfg := parseFlags()

	setupLogger(cfg.LogLevel)

	if len(cfg.ScriptIDs) == 0 || cfg.AuthKey == "" {
		fmt.Fprintln(os.Stderr, "auth-key and at least one script-id are required.")
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
	cfg := &Config{
		HTTPListen:  "0.0.0.0:8080",
		GoogleIP:    "216.239.38.120",
		FrontDomain: "www.google.com",
		LogLevel:    "info",
		H2Conns:     1,
	}

	var (
		configPath      string
		httpListen      string
		socksListen     string
		googleIP        string
		frontDomain     string
		authKey         string
		logLevel        string
		h2Conns         int
		workerURL       string
		tcpTunnelHosts  string
		httpTunnelHosts string
		bypassSS        bool
		scriptIDs       []string
	)

	flag.StringVar(&configPath, "config", defaultConfigPath, "JSON config file path (optional)")
	flag.StringVar(&httpListen, "http", cfg.HTTPListen, "HTTP CONNECT listen address")
	flag.StringVar(&socksListen, "socks", "", "SOCKS5 listen address (e.g. 0.0.0.0:1080)")
	flag.StringVar(&googleIP, "google-ip", cfg.GoogleIP, "Google frontend IP")
	flag.StringVar(&frontDomain, "front-domain", cfg.FrontDomain, "TLS SNI")
	flag.StringVar(&authKey, "auth-key", "", "shared secret")
	flag.StringVar(&logLevel, "log-level", cfg.LogLevel, "log level")
	flag.IntVar(&h2Conns, "h2-conns", cfg.H2Conns, "parallel H2 connections")
	flag.StringVar(&workerURL, "worker-url", "", "Cloudflare Worker URL")
	flag.StringVar(&tcpTunnelHosts, "tcp-tunnel-hosts", "", "TCP-tunneled hosts (IPs, CIDR, suffixes)")
	flag.StringVar(&httpTunnelHosts, "http-tunnel-hosts", "", "HTTP-tunneled host suffixes")
	flag.BoolVar(&bypassSS, "bypass-ss", false, "bypass Google SafeSearch")

	flag.Func("script-id", "Apps Script Deployment ID, repeat for load balancing",
		func(v string) error {
			v = strings.TrimSpace(v)
			if v != "" {
				scriptIDs = append(scriptIDs, v)
			}
			return nil
		})

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE: %s [flags]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr,
			"Config sources merge in order: defaults < config file < flags.")
		fmt.Fprintln(os.Stderr,
			"auth-key and at least one script-id must be supplied by at least one source.")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	flag.Parse()

	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "parsing %s: %v\n", configPath, err)
			os.Exit(2)
		}
	} else if !errors.Is(err, os.ErrNotExist) || set["config"] {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", configPath, err)
		os.Exit(2)
	}

	if set["http"] {
		cfg.HTTPListen = httpListen
	}
	if set["socks"] {
		cfg.SOCKSListen = socksListen
	}
	if set["google-ip"] {
		cfg.GoogleIP = googleIP
	}
	if set["front"] {
		cfg.FrontDomain = frontDomain
	}
	if set["auth-key"] {
		cfg.AuthKey = authKey
	}
	if set["log"] {
		cfg.LogLevel = logLevel
	}
	if set["h2-conns"] {
		cfg.H2Conns = h2Conns
	}
	if set["worker-url"] {
		cfg.WorkerURL = workerURL
	}
	if set["tcp-tunnel-hosts"] {
		cfg.TCPTunnelHosts = tcpTunnelHosts
	}
	if set["http-tunnel-hosts"] {
		cfg.HTTPTunnelHosts = httpTunnelHosts
	}
	if set["bypass-ss"] {
		cfg.BypassSS = bypassSS
	}
	if len(scriptIDs) > 0 {
		cfg.ScriptIDs = scriptIDs
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
