// Package offlinehttp provides a fail-closed default HTTP transport for tests.
// It is imported only by test files, never by application code.
package offlinehttp

import (
	"errors"
	"net"
	"net/http"
	"sync/atomic"
)

var errBlocked = errors.New("offline test blocked a non-loopback HTTP request")

type guard struct {
	base    http.RoundTripper
	blocked atomic.Uint64
}

func (g *guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.User != nil || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		g.blocked.Add(1)
		return nil, errBlocked
	}
	// Literal IPs only: no DNS resolution, localhost aliases or rebinding.
	ip := net.ParseIP(r.URL.Hostname())
	if ip == nil || !ip.IsLoopback() {
		g.blocked.Add(1)
		return nil, errBlocked
	}
	return g.base.RoundTrip(r)
}

// Install protects clients using http.DefaultTransport, including custom fake
// transports that delegate to it. Call before tests start and call the returned
// function after all tests finish. False means an unexpected request occurred,
// even if application code swallowed the transport error. Custom transports
// must be explicit fakes or delegate through this guard; this is not an OS
// network sandbox.
func Install() func() bool {
	old := http.DefaultTransport
	base := old.(*http.Transport).Clone()
	base.Proxy = nil
	g := &guard{base: base}
	http.DefaultTransport = g
	return func() bool {
		http.DefaultTransport = old
		base.CloseIdleConnections()
		return g.blocked.Load() == 0
	}
}
