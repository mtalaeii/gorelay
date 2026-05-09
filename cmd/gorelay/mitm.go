package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

const (
	mitmIdleTO   = 90 * time.Second
	mitmHeaderTO = 30 * time.Second
	maxBodySize  = 24 * 1024 * 1024
)

func mitmRelay(ctx context.Context, client net.Conn, host string, port int,
	ca *CA, relay *relayClient) error {

	var src net.Conn = client
	scheme := "http"
	if port == 443 {
		scheme = "https"
		leaf, err := ca.LeafFor(host)
		if err != nil {
			return fmt.Errorf("mint leaf for %s: %w", host, err)
		}
		tlsConn := tls.Server(client, &tls.Config{
			Certificates: []tls.Certificate{*leaf},
			NextProtos: []string{"http/1.1"},
		})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("MITM TLS handshake: %w", err)
		}
		defer tlsConn.Close()
		src = tlsConn
	}

	br := bufio.NewReader(src)
	for {
		_ = src.SetReadDeadline(time.Now().Add(mitmIdleTO))
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedConnErr(err) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}
		_ = src.SetReadDeadline(time.Time{})

		if err := serveOne(ctx, req, host, port, scheme, src, relay); err != nil {
			slog.Debug("relay request failed", "host", host, "err", err)
			writeBadGateway(src, err)
			return nil
		}
		if req.Header.Get("Connection") == "close" || req.Close {
			return nil
		}
	}
}

func serveOne(ctx context.Context, req *http.Request, host string, port int,
	scheme string, w net.Conn, relay *relayClient) error {

	url := scheme + "://" + host
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		url += ":" + strconv.Itoa(port)
	}
	url += req.URL.RequestURI()

	if req.Method == http.MethodOptions &&
		req.Header.Get("Access-Control-Request-Method") != "" {
		return writeCORSPreflight(w, req.Header)
	}

	var body []byte
	if req.ContentLength != 0 || req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		if len(b) > maxBodySize {
			return errors.New("request body exceeds limit")
		}
		body = b
	}

	slog.Debug("relay", "method", req.Method, "url", url, "body", len(body))

	rctx, cancel := context.WithTimeout(ctx, relayRequestTO)
	defer cancel()

	status, hdrs, respBody, err := relay.Fetch(rctx, req.Method, url, req.Header, body)
	if err != nil {
		return err
	}

	return writeUpstreamResponse(w, status, hdrs, respBody)
}

func writeUpstreamResponse(w net.Conn, status int, hdrs http.Header, body []byte) error {
	hdrs.Del("Connection")
	hdrs.Del("Transfer-Encoding")
	hdrs.Del("Content-Length")
	hdrs.Del("Content-Encoding")
	hdrs.Set("Content-Length", strconv.Itoa(len(body)))

	resp := &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdrs,
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
	dump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	if _, err := w.Write(dump); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func writeBadGateway(w net.Conn, cause error) {
	hint := classifyRelayErr(cause)
	if hint == "" {
		hint = cause.Error()
	}
	body := "gorelay: upstream relay failed\n\n" + hint + "\n"
	resp := "HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, _ = w.Write([]byte(resp))
}

func writeCORSPreflight(w net.Conn, reqHdr http.Header) error {
	origin := reqHdr.Get("Origin")
	method := reqHdr.Get("Access-Control-Request-Method")
	headers := reqHdr.Get("Access-Control-Request-Headers")
	if origin == "" {
		origin = "*"
	}
	resp := "HTTP/1.1 204 No Content\r\n" +
		"Access-Control-Allow-Origin: " + origin + "\r\n" +
		"Access-Control-Allow-Methods: " + method + "\r\n" +
		"Access-Control-Allow-Headers: " + headers + "\r\n" +
		"Access-Control-Allow-Credentials: true\r\n" +
		"Access-Control-Max-Age: 600\r\n" +
		"Vary: Origin\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, err := w.Write([]byte(resp))
	return err
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer")
}
