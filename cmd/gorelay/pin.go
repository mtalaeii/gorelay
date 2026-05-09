package main

import (
	"strings"
	"sync"
	"time"
)

const (
	pinFailThreshold = 3
	pinFailWindow    = 5 * time.Second
	pinSuppressFor   = 30 * time.Second
)

type pinTracker struct {
	mu    sync.Mutex
	state map[string]*pinState
}

type pinState struct {
	fails       int
	firstFailAt time.Time
	suppressUntil time.Time
}

func newPinTracker() *pinTracker {
	return &pinTracker{state: make(map[string]*pinState)}
}

func (t *pinTracker) suppressed(host string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[host]
	if s == nil {
		return false
	}
	if now.Before(s.suppressUntil) {
		return true
	}
	if !s.suppressUntil.IsZero() {
		delete(t.state, host)
	}
	return false
}

func (t *pinTracker) recordFail(host string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.state[host]
	if s == nil || now.Sub(s.firstFailAt) > pinFailWindow {
		s = &pinState{firstFailAt: now}
		t.state[host] = s
	}
	s.fails++
	if s.fails >= pinFailThreshold && s.suppressUntil.IsZero() {
		s.suppressUntil = now.Add(pinSuppressFor)
		return true
	}
	return false
}

func (t *pinTracker) recordSuccess(host string) {
	t.mu.Lock()
	delete(t.state, host)
	t.mu.Unlock()
}

func isMITMHandshakeErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "MITM TLS handshake")
}
