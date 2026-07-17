// Package middleware — per-IP token-bucket rate limiter.
//
// RateLimit returns a gin handler that enforces a per-second request cap
// per client IP using a token bucket (golang.org/x/time/rate). Buckets
// are kept in a sync.Map keyed by IP; a background goroutine evicts
// entries that have been idle for more than five minutes every two
// minutes so a burst of one-off clients can't grow the map unbounded.
//
// When a bucket is exhausted the handler responds 429 Too Many Requests
// with a Retry-After: 1 header (the bucket refills at perSecond tokens
// per second, so the wait is at most one second for any reasonable
// perSecond value).
package middleware

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// rateLimiter is the internal state for one client IP. lastSeen is
// updated on every request so the eviction goroutine can drop idle
// entries; it is read/written under no lock because rate.Limiter.Allow
// is already goroutine-safe and lastSeen is only used as a hint (an
// occasional stale read just delays eviction by one cycle).
type rateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiterStore holds the per-IP buckets. A new store is created per
// RateLimit invocation so each route group can have its own perSecond
// budget if desired.
type rateLimiterStore struct {
	mu        sync.Mutex // protects the buckets map during eviction sweep
	buckets   sync.Map   // map[string]*rateLimiter
	perSecond int
}

// idleEvictionInterval is how often the background goroutine wakes up
// to drop idle buckets.
const idleEvictionInterval = 2 * time.Minute

// idleEvictionMaxAge is the cutoff — buckets older than this with no
// activity are deleted.
const idleEvictionMaxAge = 5 * time.Minute

// RateLimit returns a gin middleware that enforces a per-IP token-bucket
// cap of perSecond requests per second. A perSecond value <= 0 disables
// limiting (the middleware becomes a no-op), which keeps callers like
// the default Server.Register path that read perSecond from config
// simple — they can pass through whatever the operator configured.
func RateLimit(perSecond int) gin.HandlerFunc {
	if perSecond <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	store := &rateLimiterStore{perSecond: perSecond}
	go store.evictIdle()
	return store.handler
}

// handler is the actual gin middleware. It looks up (or creates) the
// caller's bucket and checks Allow(). On denial it short-circuits with
// 429 + Retry-After.
func (s *rateLimiterStore) handler(c *gin.Context) {
	ip := clientIP(c)
	rl := s.get(ip)
	if !rl.limiter.Allow() {
		c.Header("Retry-After", strconv.Itoa(1))
		c.AbortWithStatusJSON(429, gin.H{
			"error":               "rate limit exceeded",
			"retry_after_seconds": 1,
		})
		return
	}
	c.Next()
}

// get returns the bucket for ip, creating one on first contact. The
// sync.Map LoadOrStore ensures only one bucket is created per IP even
// under concurrent first-requests.
func (s *rateLimiterStore) get(ip string) *rateLimiter {
	now := time.Now()
	if v, ok := s.buckets.Load(ip); ok {
		rl := v.(*rateLimiter)
		rl.lastSeen = now
		return rl
	}
	rl := &rateLimiter{
		limiter:  rate.NewLimiter(rate.Limit(s.perSecond), s.perSecond),
		lastSeen: now,
	}
	if actual, loaded := s.buckets.LoadOrStore(ip, rl); loaded {
		// Another goroutine raced us; use theirs.
		rl = actual.(*rateLimiter)
		rl.lastSeen = now
	}
	return rl
}

// evictIdle wakes up every idleEvictionInterval and deletes buckets
// that haven't been touched in idleEvictionMaxAge. It runs for the
// lifetime of the process; there's no shutdown channel because the
// cost of one lingering goroutine at exit is negligible.
func (s *rateLimiterStore) evictIdle() {
	ticker := time.NewTicker(idleEvictionInterval)
	defer ticker.Stop()
	cutoff := idleEvictionMaxAge
	for range ticker.C {
		now := time.Now()
		s.buckets.Range(func(key, value any) bool {
			rl := value.(*rateLimiter)
			if now.Sub(rl.lastSeen) > cutoff {
				s.buckets.Delete(key)
			}
			return true
		})
	}
}

// clientIP extracts the caller's IP from the gin context. We prefer
// gin's ClientIP helper (which honours X-Forwarded-For / X-Real-IP when
// the trusted-proxies chain is configured) and fall back to
// RemoteAddr. An empty IP (e.g. unix socket) is bucketed under the
// literal "<unknown>" so all such requests share one bucket rather
// than each getting its own.
func clientIP(c *gin.Context) string {
	if ip := c.ClientIP(); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	if host == "" {
		return "<unknown>"
	}
	return host
}
