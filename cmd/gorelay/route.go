package main

import (
	"net"
	"net/url"
	"strings"
)

type routeMode int

const (
	routeRelay routeMode = iota
	routeDirect
	routeSNIRewrite
)

func (r routeMode) String() string {
	switch r {
	case routeDirect:
		return "direct"
	case routeSNIRewrite:
		return "sni-rewrite"
	default:
		return "relay"
	}
}

var sniRewriteSuffixes = []string{
	"youtube.com",
	"youtu.be",
	"youtube-nocookie.com",
	"ytimg.com",
	"ggpht.com",
	"gvt1.com",
	"gvt2.com",
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"google-analytics.com",
	"googletagmanager.com",
	"googletagservices.com",
	"fonts.googleapis.com",
}

var directGoogleSuffixes = []string{
	"google.com",
	"gstatic.com",
	"googleapis.com",
	"googleusercontent.com",
	"google.co",
	"goog",
	"withgoogle.com",
	"appspot.com",
}

func classify(host string) routeMode {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if hostHasSuffix(h, sniRewriteSuffixes) {
		return routeSNIRewrite
	}
	if hostHasSuffix(h, directGoogleSuffixes) {
		return routeDirect
	}
	return routeRelay
}

func hostHasSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

type hostMatcher struct {
	exactIPs map[string]struct{}
	cidrs    []*net.IPNet
	suffixes []string
}

func parseHostMatcher(raw string) *hostMatcher {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	m := &hostMatcher{exactIPs: make(map[string]struct{})}
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				m.cidrs = append(m.cidrs, ipnet)
				continue
			}
		}
		if net.ParseIP(e) != nil {
			m.exactIPs[e] = struct{}{}
			continue
		}
		s := strings.ToLower(strings.TrimPrefix(e, "."))
		s = strings.TrimSuffix(s, ".")
		if s != "" {
			m.suffixes = append(m.suffixes, s)
		}
	}
	if len(m.exactIPs) == 0 && len(m.cidrs) == 0 && len(m.suffixes) == 0 {
		return nil
	}
	return m
}

func (m *hostMatcher) matchesHost(host string) bool {
	if m == nil {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(host); ip != nil {
		if _, ok := m.exactIPs[host]; ok {
			return true
		}
		for _, n := range m.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	h := strings.ToLower(host)
	for _, suf := range m.suffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

func (m *hostMatcher) matchesURL(u string) bool {
	if m == nil {
		return false
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return m.matchesHost(parsed.Hostname())
}
