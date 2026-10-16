package transport

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// clientID identifies a client for rate limiting and auth-failure
// counting: an IPv4 address (/32), or an IPv6 /64 (one site's allocation,
// so a client cannot multiply its budget by rotating addresses within it).
// The zero prefix stands for a connection whose address cannot be parsed.
type clientID = netip.Prefix

// maxTrackedClients bounds each limiter's table.
const maxTrackedClients = 4096

// clientAddr is the connection's peer address. Only when that peer is one
// of SHELL_MCP_TRUSTED_PROXIES is X-Forwarded-For used, and then only its
// last entry (of the last header): the one that proxy appended. Entries
// before it were written by the client and are never used; an unparsable
// last entry falls back to the peer. A request from any other address
// counts against its own peer address, whatever headers it carries.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	var peer netip.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		peer = ap.Addr().WithZone("").Unmap()
	}
	if !peer.IsValid() || !slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(peer) }) {
		return peer
	}
	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) == 0 {
		return peer
	}
	last := vals[len(vals)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	a, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return peer
	}
	return a.WithZone("").Unmap()
}

func keyOf(a netip.Addr) clientID {
	switch {
	case !a.IsValid():
		return clientID{}
	case a.Is4():
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// ipLimiter is a token bucket per client: perMin tokens a minute, at most
// perMin stored, one per request.
type ipLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	buckets map[clientID]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(perMin int, now func() time.Time) *ipLimiter {
	return &ipLimiter{rate: float64(perMin) / 60, burst: float64(perMin), now: now, buckets: map[clientID]*bucket{}}
}

// allow takes one token for c, or reports how long until one is available.
func (l *ipLimiter) allow(c clientID) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[c]
	if !ok {
		l.makeRoom(now)
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[c] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// makeRoom keeps the table below maxTrackedClients: buckets that have
// refilled completely carry no state and go first, then the least recently
// used. Called with l.mu held.
func (l *ipLimiter) makeRoom(now time.Time) {
	if len(l.buckets) < maxTrackedClients {
		return
	}
	for c, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, c)
		}
	}
	for len(l.buckets) >= maxTrackedClients {
		var oldest clientID
		var oldestLast time.Time
		first := true
		for c, b := range l.buckets {
			if first || b.last.Before(oldestLast) {
				oldest, oldestLast, first = c, b.last, false
			}
		}
		delete(l.buckets, oldest)
	}
}

func (l *ipLimiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
