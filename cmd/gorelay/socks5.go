package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	socks5Version = 0x05
	socks5NoAuth  = 0x00
	socks5Connect = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

func socks5Negotiate(c net.Conn) (host string, port int, err error) {
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return "", 0, err
	}
	if greet[0] != socks5Version {
		return "", 0, errors.New("not socks5")
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	noAuth := false
	for _, m := range methods {
		if m == socks5NoAuth {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{socks5Version, 0xFF})
		return "", 0, errors.New("client requires auth (we only support no-auth)")
	}
	if _, err := c.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return "", 0, err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != socks5Version {
		return "", 0, errors.New("bad version on request")
	}
	if req[1] != socks5Connect {
		_, _ = c.Write([]byte{socks5Version, 0x07, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		return "", 0, errors.New("only CONNECT supported")
	}
	switch req[3] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	default:
		_, _ = c.Write([]byte{socks5Version, 0x08, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		return "", 0, errors.New("unknown atyp")
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(pb[:]))

	if _, err := c.Write([]byte{socks5Version, 0x00, 0, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", 0, err
	}
	return host, port, nil
}
