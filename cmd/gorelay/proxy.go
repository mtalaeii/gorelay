package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type proxy struct {
	cfg       *Config
	ca        *CA
	relay     *relayClient
	tunnel    *tcpTunnelClient
	tcpTunnel *hostMatcher
	pinTrack  *pinTracker
}

func newProxy(cfg *Config, ca *CA, relay *relayClient) *proxy {
	p := &proxy{
		cfg:       cfg,
		ca:        ca,
		relay:     relay,
		tcpTunnel: parseHostMatcher(cfg.TCPTunnelHosts),
		pinTrack:  newPinTracker(),
	}
	if cfg.WorkerURL != "" {
		p.tunnel = newTCPTunnelClient(relay, cfg.WorkerURL, cfg.AuthKey)
		slog.Info("worker enabled",
			"url", cfg.WorkerURL,
			"tcp_tunnel_hosts", cfg.TCPTunnelHosts != "",
			"http_tunnel_hosts", cfg.HTTPTunnelHosts != "")
	}
	return p
}

func (p *proxy) Run(ctx context.Context) error {
	httpLn, err := net.Listen("tcp", p.cfg.HTTPListen)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	defer httpLn.Close()
	slog.Info("HTTP proxy listening", "addr", httpLn.Addr())

	var socksLn net.Listener
	if p.cfg.SOCKSListen != "" {
		socksLn, err = net.Listen("tcp", p.cfg.SOCKSListen)
		if err != nil {
			return fmt.Errorf("socks listen: %w", err)
		}
		defer socksLn.Close()
		slog.Info("SOCKS5 proxy listening", "addr", socksLn.Addr())
	}

	logLANHints(httpLn.Addr(), socksLn)

	go func() {
		<-ctx.Done()
		_ = httpLn.Close()
		if socksLn != nil {
			_ = socksLn.Close()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.acceptLoop(ctx, httpLn, p.handleHTTP)
	}()
	if socksLn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.acceptLoop(ctx, socksLn, p.handleSOCKS5)
		}()
	}
	wg.Wait()
	return nil
}

func (p *proxy) handleSOCKS5(ctx context.Context, c net.Conn) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	host, port, err := socks5Negotiate(c)
	if err != nil {
		slog.Debug("socks5 negotiate failed", "err", err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	p.dispatchTunnel(ctx, c, host, port)
}

func (p *proxy) acceptLoop(ctx context.Context, ln net.Listener,
	handler func(context.Context, net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			slog.Debug("accept", "err", err)
			return
		}
		tcpKeepalive(conn)
		go handler(ctx, conn)
	}
}

func (p *proxy) handleHTTP(ctx context.Context, c net.Conn) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	if req.Method == http.MethodGet &&
		(req.URL.Path == "/ca.crt" || req.URL.Path == "/ca") {
		serveCACert(c, p.ca)
		return
	}

	if req.Method == http.MethodConnect {
		p.dispatchConnect(ctx, c, req.Host)
		return
	}

	if req.URL.Scheme == "http" && req.URL.Host != "" {
		host, port := splitHostPort(req.URL.Host, 80)
		_ = serveOne(ctx, req, host, port, "http", c, p.relay)
		return
	}

	writeText(c, http.StatusMethodNotAllowed,
		"gorelay only handles CONNECT and absolute-form HTTP requests")
}

func (p *proxy) dispatchConnect(ctx context.Context, c net.Conn, target string) {
	host, port := splitHostPort(target, 443)
	if host == "" {
		writeText(c, http.StatusBadRequest, "bad CONNECT target")
		return
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	p.dispatchTunnel(ctx, c, host, port)
}

func (p *proxy) dispatchTunnel(ctx context.Context, c net.Conn,
	host string, port int) {

	if p.tunnel != nil && p.tcpTunnel.matchesHost(host) {
		slog.Info("tunnel", "host", host, "port", port, "mode", "tcp-tunnel")
		err := p.tunnel.Tunnel(ctx, c, host, port)
		if err != nil && !isClosedConnErr(err) {
			slog.Debug("tunnel ended with error",
				"host", host, "mode", "tcp-tunnel", "err", err)
		}
		return
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			slog.Debug("ignoring IPv6 CONNECT", "host", host, "port", port)
			return
		}
		slog.Info("tunnel", "host", host, "port", port, "mode", "direct-ip")
		upstream, derr := net.DialTimeout("tcp4",
			net.JoinHostPort(host, strconv.Itoa(port)), ipLiteralDialTimeout)
		if derr != nil {
			slog.Debug("tunnel ended with error",
				"host", host, "mode", "direct-ip", "err", derr)
			return
		}
		err := splice(c, upstream)
		upstream.Close()
		if err != nil && !isClosedConnErr(err) {
			slog.Debug("tunnel ended with error",
				"host", host, "mode", "direct-ip", "err", err)
		}
		return
	}

	mode := classify(host)
	httpTunnel := p.relay.routesViaHTTPTunnel(host)
	if httpTunnel {
		mode = routeRelay
	}
	modeStr := mode.String()
	if httpTunnel {
		modeStr = "http-tunnel"
	}
	slog.Info("tunnel", "host", host, "port", port, "mode", modeStr)

	var err error
	switch mode {
	case routeDirect:
		err = directTunnel(c, host, port)
	case routeSNIRewrite:
		if port == 443 {
			err = sniRewriteTunnel(c, host, port, p.ca,
				p.cfg.GoogleIP, p.cfg.FrontDomain)
		} else {
			err = directTunnel(c, host, port)
		}
	case routeRelay:
		if port != 443 && port != 80 {
			slog.Debug("dropping non-HTTP port",
				"host", host, "port", port)
			return
		}
		if port == 443 && p.pinTrack.suppressed(host) {
			slog.Debug("cert-pin suppressed", "host", host)
			return
		}
		err = mitmRelay(ctx, c, host, port, p.ca, p.relay)
		if port == 443 {
			if isMITMHandshakeErr(err) {
				if p.pinTrack.recordFail(host) {
					slog.Debug("entering cert-pin suppression",
						"host", host, "for", pinSuppressFor)
				}
			} else if err == nil {
				p.pinTrack.recordSuccess(host)
			}
		}
	}
	if err != nil && !isClosedConnErr(err) {
		slog.Debug("tunnel ended with error",
			"host", host, "mode", mode.String(), "err", err)
	}
}

func splitHostPort(s string, defaultPort int) (string, int) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil {
			return h, defaultPort
		}
		return h, port
	}
	return s, defaultPort
}

func serveCACert(c net.Conn, ca *CA) {
	pem := ca.CertPEM()
	hdr := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/x-x509-ca-cert\r\n" +
		"Content-Disposition: attachment; filename=\"gorelay-ca.crt\"\r\n" +
		"Content-Length: " + strconv.Itoa(len(pem)) + "\r\n" +
		"Connection: close\r\n\r\n"
	_, _ = c.Write([]byte(hdr))
	_, _ = c.Write(pem)
}

func writeText(c net.Conn, status int, body string) {
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	_, _ = c.Write([]byte(resp))
}

func logLANHints(httpAddr net.Addr, socksLn net.Listener) {
	httpTCP, ok := httpAddr.(*net.TCPAddr)
	if !ok || !httpTCP.IP.IsUnspecified() {
		return
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	var lanIPs []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			lanIPs = append(lanIPs, ipNet.IP.String())
		}
	}
	socksPort := 0
	if socksLn != nil {
		if a, ok := socksLn.Addr().(*net.TCPAddr); ok {
			socksPort = a.Port
		}
	}
	for _, ip := range lanIPs {
		args := []any{
			"http", "http://" + ip + ":" + strconv.Itoa(httpTCP.Port),
			"ca_download", "http://" + ip + ":" + strconv.Itoa(httpTCP.Port) + "/ca.crt",
		}
		if socksPort > 0 {
			args = append(args, "socks5", ip+":"+strconv.Itoa(socksPort))
		}
		slog.Info("reach the proxy from a LAN device", args...)
	}
}

