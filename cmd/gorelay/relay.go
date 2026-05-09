package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	relayMaxBody    = 24 * 1024 * 1024
	relayDialTO     = 10 * time.Second
	relayRequestTO  = 30 * time.Second
	relayIdleTO     = 90 * time.Second
	relayMaxIdle    = 16
	relayMaxIdleHst = 16

	maxH2Conns = 16

	batchWindowMicro = 15 * time.Millisecond
	batchWindowMacro = 120 * time.Millisecond
	batchMax         = 64
)

type relayClient struct {
	cfg          *Config
	httpClients  []*http.Client
	nextClient   uint64
	execURLs     []string
	nextExecURL  uint64
	httpTunnel   *hostMatcher
	batchMu      sync.Mutex
	batchPending []*batchEntry
	batchTimer   *time.Timer
}

type batchEntry struct {
	payload map[string]any
	result  chan batchResult
}

type batchResult struct {
	status  int
	headers http.Header
	body    []byte
	err     error
}

func newRelayClient(cfg *Config) *relayClient {
	n := cfg.H2Conns
	if n < 1 {
		n = 1
	}
	if n > maxH2Conns {
		n = maxH2Conns
	}
	clients := make([]*http.Client, n)
	for i := range clients {
		clients[i] = newRelayHTTPClient(cfg)
	}
	if n > 1 {
		slog.Info("relay: parallel HTTP/2 connections enabled", "count", n)
	}

	execURLs := make([]string, len(cfg.ScriptIDs))
	for i, id := range cfg.ScriptIDs {
		execURLs[i] = "https://script.google.com/macros/s/" + id + "/exec"
	}
	if len(execURLs) > 1 {
		slog.Info("relay: multi-script load balancing enabled", "count", len(execURLs))
	}

	return &relayClient{
		cfg:         cfg,
		httpClients: clients,
		execURLs:    execURLs,
		httpTunnel:  parseHostMatcher(cfg.HTTPTunnelHosts),
	}
}

func (r *relayClient) pickExecURL() string {
	if len(r.execURLs) == 1 {
		return r.execURLs[0]
	}
	n := atomic.AddUint64(&r.nextExecURL, 1) - 1
	return r.execURLs[int(n%uint64(len(r.execURLs)))]
}

func (r *relayClient) routesViaHTTPTunnel(host string) bool {
	return r.cfg.WorkerURL != "" && r.httpTunnel.matchesHost(host)
}

func newRelayHTTPClient(cfg *Config) *http.Client {
	dialer := &net.Dialer{Timeout: relayDialTO, KeepAlive: 30 * time.Second}

	tlsCfg := &tls.Config{
		ServerName: cfg.FrontDomain,
		NextProtos: []string{"h2", "http/1.1"},
	}

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, network,
				net.JoinHostPort(cfg.GoogleIP, "443"))
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, tlsCfg.Clone())
			if err := c.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return c, nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          relayMaxIdle,
		MaxIdleConnsPerHost:   relayMaxIdleHst,
		IdleConnTimeout:       relayIdleTO,
		ResponseHeaderTimeout: relayRequestTO,
	}
	return &http.Client{Transport: transport, Timeout: relayRequestTO}
}

func (r *relayClient) pickClient() *http.Client {
	if len(r.httpClients) == 1 {
		return r.httpClients[0]
	}
	n := atomic.AddUint64(&r.nextClient, 1) - 1
	return r.httpClients[int(n%uint64(len(r.httpClients)))]
}

func (r *relayClient) Close() {
	for _, c := range r.httpClients {
		c.CloseIdleConnections()
	}
}

type relayResp struct {
	Status  int                        `json:"s"`
	Headers map[string]json.RawMessage `json:"h"`
	Body    string                     `json:"b"`
	Gz      int                        `json:"gz"`
	Err     string                     `json:"e"`
}

func (r *relayClient) Fetch(ctx context.Context, method, target string,
	headers http.Header, body []byte) (int, http.Header, []byte, error) {

	if r.cfg.WorkerURL != "" && r.httpTunnel.matchesURL(target) {
		return r.fetchViaHTTPTunnel(ctx, method, target, headers, body)
	}
	return r.submit(ctx, buildPayload(method, target, headers, body))
}

func (r *relayClient) fetchViaHTTPTunnel(ctx context.Context, method, target string,
	headers http.Header, body []byte) (int, http.Header, []byte, error) {

	inner := buildPayload(method, target, headers, body)
	inner["k"] = r.cfg.AuthKey
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return 0, nil, nil, err
	}

	outer := buildPayload(http.MethodPost, r.cfg.WorkerURL,
		http.Header{"Content-Type": []string{"application/json"}}, innerJSON)

	_, _, exitBody, err := r.submit(ctx, outer)
	if err != nil {
		return 0, nil, nil, err
	}
	return parseEnvelope(exitBody)
}

func (r *relayClient) submitImmediate(ctx context.Context, payload map[string]any) (
	int, http.Header, []byte, error) {

	full := payload
	full["k"] = r.cfg.AuthKey
	jsonBody, err := json.Marshal(full)
	if err != nil {
		return 0, nil, nil, err
	}
	raw, err := r.postRaw(ctx, jsonBody)
	if err != nil {
		return 0, nil, nil, err
	}
	return parseEnvelope(raw)
}

func (r *relayClient) submit(ctx context.Context, payload map[string]any) (
	int, http.Header, []byte, error) {

	entry := &batchEntry{
		payload: payload,
		result:  make(chan batchResult, 1),
	}

	r.batchMu.Lock()
	r.batchPending = append(r.batchPending, entry)
	if len(r.batchPending) >= batchMax {
		batch := r.batchPending
		r.batchPending = nil
		if r.batchTimer != nil {
			r.batchTimer.Stop()
			r.batchTimer = nil
		}
		r.batchMu.Unlock()
		go r.sendBatch(batch)
	} else if r.batchTimer == nil {
		r.batchTimer = time.AfterFunc(batchWindowMicro, r.timerFlush)
		r.batchMu.Unlock()
	} else {
		r.batchTimer.Reset(batchWindowMacro)
		r.batchMu.Unlock()
	}

	select {
	case res := <-entry.result:
		return res.status, res.headers, res.body, res.err
	case <-ctx.Done():
		return 0, nil, nil, ctx.Err()
	}
}

func (r *relayClient) timerFlush() {
	r.batchMu.Lock()
	batch := r.batchPending
	r.batchPending = nil
	r.batchTimer = nil
	r.batchMu.Unlock()
	if len(batch) > 0 {
		r.sendBatch(batch)
	}
}

func (r *relayClient) sendBatch(batch []*batchEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), relayRequestTO)
	defer cancel()

	if len(batch) == 1 {
		r.sendSingleton(ctx, batch[0])
		return
	}
	r.sendMulti(ctx, batch)
}

func (r *relayClient) sendSingleton(ctx context.Context, e *batchEntry) {
	full := e.payload
	full["k"] = r.cfg.AuthKey
	jsonBody, err := json.Marshal(full)
	if err != nil {
		e.result <- batchResult{err: err}
		return
	}
	raw, err := r.postRaw(ctx, jsonBody)
	if err != nil {
		e.result <- batchResult{err: err}
		return
	}
	status, hdrs, body, perr := parseEnvelope(raw)
	e.result <- batchResult{status: status, headers: hdrs, body: body, err: perr}
}

func (r *relayClient) sendMulti(ctx context.Context, batch []*batchEntry) {
	items := make([]map[string]any, len(batch))
	for i, e := range batch {
		items[i] = e.payload
	}
	outer := map[string]any{
		"k": r.cfg.AuthKey,
		"q": items,
	}
	jsonBody, err := json.Marshal(outer)
	if err != nil {
		fanoutErr(batch, err)
		return
	}
	raw, err := r.postRaw(ctx, jsonBody)
	if err != nil {
		fanoutErr(batch, err)
		return
	}

	var bResp struct {
		Q []*relayResp `json:"q"`
		E string       `json:"e"`
	}
	if err := json.Unmarshal(raw, &bResp); err != nil {
		head := raw
		if len(head) > 120 {
			head = head[:120]
		}
		fanoutErr(batch, fmt.Errorf("decode batch JSON: %w (first %d bytes: %q)",
			err, len(head), head))
		return
	}
	if bResp.E != "" {
		fanoutErr(batch, fmt.Errorf("relay error: %s", bResp.E))
		return
	}

	for i, e := range batch {
		if i >= len(bResp.Q) || bResp.Q[i] == nil {
			e.result <- batchResult{err: errors.New("missing item in batch response")}
			continue
		}
		env := bResp.Q[i]
		if env.Err != "" {
			e.result <- batchResult{err: fmt.Errorf("relay error: %s", env.Err)}
			continue
		}
		body, err := decodeRelayBody(env)
		if err != nil {
			e.result <- batchResult{err: err}
			continue
		}
		e.result <- batchResult{
			status:  env.Status,
			headers: decodeHeaders(env.Headers),
			body:    body,
		}
	}
}

func fanoutErr(batch []*batchEntry, err error) {
	for _, e := range batch {
		e.result <- batchResult{err: err}
	}
}

func (r *relayClient) postRaw(ctx context.Context, jsonBody []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.pickExecURL(),
		bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := r.pickClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay returned HTTP %d", resp.StatusCode)
	}
	return readMaybeGzip(resp, relayMaxBody)
}

func parseEnvelope(raw []byte) (int, http.Header, []byte, error) {
	var env relayResp
	if err := json.Unmarshal(raw, &env); err != nil {
		head := raw
		if len(head) > 120 {
			head = head[:120]
		}
		return 0, nil, nil, fmt.Errorf("decode relay JSON: %w (first %d bytes: %q)",
			err, len(head), head)
	}
	if env.Err != "" {
		return 0, nil, nil, fmt.Errorf("relay error: %s", env.Err)
	}
	body, err := decodeRelayBody(&env)
	if err != nil {
		return 0, nil, nil, err
	}
	return env.Status, decodeHeaders(env.Headers), body, nil
}

func decodeRelayBody(env *relayResp) ([]byte, error) {
	body, err := base64.StdEncoding.DecodeString(env.Body)
	if err != nil {
		return nil, fmt.Errorf("decode body base64: %w", err)
	}
	if env.Gz == 1 {
		body, err = gunzipBytes(body)
		if err != nil {
			return nil, fmt.Errorf("decompress relay body: %w", err)
		}
	}
	return body, nil
}

func buildPayload(method, target string,
	headers http.Header, body []byte) map[string]any {

	p := map[string]any{
		"u": target,
		"m": method,
		"r": false,
	}
	if len(headers) > 0 {
		p["h"] = sanitizeReqHeaders(headers)
	}
	if len(body) > 0 {
		p["b"] = base64.StdEncoding.EncodeToString(body)
		if ct := headers.Get("Content-Type"); ct != "" {
			p["ct"] = ct
		}
	}
	return p
}

var stripReqHeaders = map[string]struct{}{
	"connection":          {},
	"proxy-connection":    {},
	"proxy-authorization": {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"x-forwarded-for":     {},
	"x-forwarded-host":    {},
	"x-forwarded-proto":   {},
	"x-real-ip":           {},
	"forwarded":           {},
	"via":                 {},
	"accept-encoding":     {},
}

func sanitizeReqHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if _, drop := stripReqHeaders[strings.ToLower(k)]; drop {
			continue
		}
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func decodeHeaders(in map[string]json.RawMessage) http.Header {
	out := make(http.Header, len(in))
	for k, raw := range in {
		var single string
		if json.Unmarshal(raw, &single) == nil {
			out.Add(k, single)
			continue
		}
		var multi []string
		if json.Unmarshal(raw, &multi) == nil {
			for _, v := range multi {
				out.Add(k, v)
			}
		}
	}
	return out
}

func readMaybeGzip(resp *http.Response, max int64) ([]byte, error) {
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return io.ReadAll(io.LimitReader(r, max+1))
}

func gunzipBytes(b []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	out, err := io.ReadAll(io.LimitReader(gz, relayMaxBody+1))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func classifyRelayErr(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized"):
		return "auth-key / exit-psk mismatch with the deployed script"
	case strings.Contains(msg, "quota") || strings.Contains(msg, "exceeded"),
		strings.Contains(msg, "too many times"):
		return "Apps Script daily quota exhausted (resets at midnight US/Pacific)"
	case strings.Contains(msg, "not_found"):
		return "wrong --script-id (or you forgot to redeploy after editing code.gs)"
	case strings.Contains(msg, "loop"):
		return "exit-node loop detected — check --exit-url isn't pointing at Apps Script"
	case errors.Is(err, context.DeadlineExceeded):
		return "relay timeout (Apps Script took too long; the target may be slow)"
	}
	return ""
}
