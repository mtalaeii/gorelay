package main

import (
	"context"
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
	"time"
)

const (
	tunnelOpenTimeout  = 10 * time.Second
	tunnelWriteTimeout = 30 * time.Second
	tunnelReadTimeout  = 35 * time.Second
	tunnelCloseTimeout = 5 * time.Second
	tunnelChunkBytes   = 256 * 1024
)

type tcpTunnelClient struct {
	relay *relayClient
	url   string
	psk   string
}

func newTCPTunnelClient(relay *relayClient, url, psk string) *tcpTunnelClient {
	return &tcpTunnelClient{
		relay: relay,
		url:   strings.TrimRight(url, "/"),
		psk:   psk,
	}
}

func (t *tcpTunnelClient) Tunnel(ctx context.Context, client net.Conn,
	host string, port int) error {

	openCtx, openCancel := context.WithTimeout(ctx, tunnelOpenTimeout)
	sid, err := t.openSession(openCtx, host, port)
	openCancel()
	if err != nil {
		return fmt.Errorf("open tunnel session: %w", err)
	}
	slog.Debug("tcp tunnel: session opened", "sid", sid, "host", host, "port", port)

	loopCtx, loopCancel := context.WithCancel(ctx)
	defer loopCancel()

	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	report := func(label string, e error) {
		if e == nil || errors.Is(e, io.EOF) || errors.Is(e, context.Canceled) {
			return
		}
		slog.Debug("tcp tunnel loop ended", "sid", sid, "side", label, "err", e)
		once.Do(func() { firstErr = e })
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer loopCancel()
		report("write", t.writeLoop(loopCtx, client, sid))
	}()
	go func() {
		defer wg.Done()
		defer loopCancel()
		report("read", t.readLoop(loopCtx, client, sid))
	}()
	wg.Wait()

	closeCtx, closeCancel := context.WithTimeout(context.Background(), tunnelCloseTimeout)
	defer closeCancel()
	if cerr := t.closeSession(closeCtx, sid); cerr != nil {
		slog.Debug("tcp tunnel: close session failed", "sid", sid, "err", cerr)
	}
	return firstErr
}

func (t *tcpTunnelClient) writeLoop(ctx context.Context, client net.Conn, sid string) error {
	buf := make([]byte, tunnelChunkBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := client.Read(buf)
		if n > 0 {
			wctx, cancel := context.WithTimeout(ctx, tunnelWriteTimeout)
			werr := t.writeChunk(wctx, sid, buf[:n])
			cancel()
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func (t *tcpTunnelClient) readLoop(ctx context.Context, client net.Conn, sid string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rctx, cancel := context.WithTimeout(ctx, tunnelReadTimeout)
		body, eof, err := t.readChunk(rctx, sid)
		cancel()
		if err != nil {
			return err
		}
		if len(body) > 0 {
			if _, werr := client.Write(body); werr != nil {
				return werr
			}
		}
		if eof {
			return nil
		}
	}
}

type openResp struct {
	SID string `json:"sid"`
	E   string `json:"e"`
}

func (t *tcpTunnelClient) openSession(ctx context.Context, host string, port int) (string, error) {
	body, _ := json.Marshal(map[string]any{"k": t.psk, "host": host, "port": port})
	status, _, raw, err := t.relayPost(ctx, "/tunnel/open", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("open returned HTTP %d: %s", status, snippet(raw))
	}
	var r openResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("open: bad JSON: %w (%s)", err, snippet(raw))
	}
	if r.E != "" {
		return "", fmt.Errorf("open: %s", r.E)
	}
	if r.SID == "" {
		return "", errors.New("open: empty sid")
	}
	return r.SID, nil
}

type writeResp struct {
	OK bool   `json:"ok"`
	E  string `json:"e"`
}

func (t *tcpTunnelClient) writeChunk(ctx context.Context, sid string, data []byte) error {
	body, _ := json.Marshal(map[string]any{
		"k": t.psk,
		"b": base64.StdEncoding.EncodeToString(data),
	})
	status, _, raw, err := t.relayPost(ctx, "/tunnel/"+sid+"/write", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("write returned HTTP %d: %s", status, snippet(raw))
	}
	var r writeResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("write: bad JSON: %w", err)
	}
	if r.E != "" {
		return fmt.Errorf("write: %s", r.E)
	}
	return nil
}

type readResp struct {
	B   string `json:"b"`
	EOF bool   `json:"eof"`
	E   string `json:"e"`
}

func (t *tcpTunnelClient) readChunk(ctx context.Context, sid string) ([]byte, bool, error) {
	body, _ := json.Marshal(map[string]any{"k": t.psk})
	status, _, raw, err := t.relayPost(ctx, "/tunnel/"+sid+"/read", body)
	if err != nil {
		return nil, false, err
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("read returned HTTP %d: %s", status, snippet(raw))
	}
	var r readResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, false, fmt.Errorf("read: bad JSON: %w", err)
	}
	if r.E != "" && !r.EOF {
		return nil, false, fmt.Errorf("read: %s", r.E)
	}
	if r.B == "" {
		return nil, r.EOF, nil
	}
	decoded, derr := base64.StdEncoding.DecodeString(r.B)
	if derr != nil {
		return nil, false, fmt.Errorf("read: bad base64: %w", derr)
	}
	return decoded, r.EOF, nil
}

func (t *tcpTunnelClient) closeSession(ctx context.Context, sid string) error {
	body, _ := json.Marshal(map[string]any{"k": t.psk})
	status, _, raw, err := t.relayPost(ctx, "/tunnel/"+sid+"/close", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("close returned HTTP %d: %s", status, snippet(raw))
	}
	return nil
}

func (t *tcpTunnelClient) relayPost(ctx context.Context, path string, body []byte) (
	int, http.Header, []byte, error) {

	url := t.url + path
	hdr := http.Header{"Content-Type": []string{"application/json"}}

	payload := buildPayload(http.MethodPost, url, hdr, body)
	return t.relay.submitImmediate(ctx, payload)
}

func snippet(b []byte) string {
	if len(b) > 120 {
		return string(b[:120]) + "…"
	}
	return string(b)
}
