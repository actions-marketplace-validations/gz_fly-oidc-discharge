package server

import (
	"sync"
	"time"
)

// rateLimiter is a token bucket bounding the work an unauthenticated caller can
// trigger. Verification of a token whose key ID is unknown makes go-oidc refetch
// the issuer's key set, one fetch per request and with no cooldown of its own,
// so without a limit a caller can drive unbounded outbound requests.
//
// The bucket is global rather than per source address: callers arrive through
// Fly Proxy, so the only address available is a header this service would have
// to trust. A global limit means a flood can also delay a real job, which is
// the accepted trade for bounding the work a stranger can cause.
type rateLimiter struct {
	perSecond float64
	burst     float64
	now       func() time.Time

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newRateLimiter(perSecond, burst float64, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		perSecond: perSecond,
		burst:     burst,
		now:       now,
		tokens:    burst,
		last:      now(),
	}
}

// allow consumes one token, refilling first for the time since the last call.
func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens = min(l.burst, l.tokens+elapsed*l.perSecond)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
