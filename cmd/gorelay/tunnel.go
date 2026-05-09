package main

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	dialTimeout          = 10 * time.Second
	ipLiteralDialTimeout = 4 * time.Second
)

func directTunnel(client net.Conn, host string, port int) error {
	return directTunnelWithTimeout(client, host, port, dialTimeout)
}

func directTunnelWithTimeout(client net.Conn, host string, port int, timeout time.Duration) error {
	addr := net.JoinHostPort(host, itoa(port))
	upstream, err := net.DialTimeout("tcp4", addr, timeout)
	if err != nil {
		return err
	}
	defer upstream.Close()
	return splice(client, upstream)
}

func sniRewriteTunnel(client net.Conn, host string, port int,
	ca *CA, googleIP, frontDomain string) error {

	leaf, err := ca.LeafFor(host)
	if err != nil {
		return err
	}

	innerTLS := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	})
	if err := innerTLS.Handshake(); err != nil {
		return err
	}
	defer innerTLS.Close()

	upstreamAddr := net.JoinHostPort(googleIP, itoa(port))
	rawUp, err := net.DialTimeout("tcp", upstreamAddr, dialTimeout)
	if err != nil {
		return err
	}
	tcpKeepalive(rawUp)
	upstream := tls.Client(rawUp, &tls.Config{
		ServerName: frontDomain,
		NextProtos: []string{"http/1.1"},
	})
	if err := upstream.Handshake(); err != nil {
		rawUp.Close()
		return err
	}
	defer upstream.Close()

	return splice(innerTLS, upstream)
}

func splice(a, b net.Conn) error {
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	report := func(err error) {
		if err == nil || errors.Is(err, io.EOF) {
			return
		}
		once.Do(func() { firstErr = err })
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(b, a)
		report(err)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(a, b)
		report(err)
		closeWrite(a)
	}()
	wg.Wait()
	return firstErr
}

func closeWrite(c net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}

func tcpKeepalive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
