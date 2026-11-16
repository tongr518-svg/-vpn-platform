package main

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"
)

type rateBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*rateBucket
	lastCleanup time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets:     make(map[string]*rateBucket),
		lastCleanup: time.Now(),
	}
}

// allow implements a token bucket and returns the suggested retry delay.
func (l *rateLimiter) allow(key string, capacity float64, refillPerSecond float64) (bool, time.Duration) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastCleanup) >= 10*time.Minute {
		for bucketKey, bucket := range l.buckets {
			if now.Sub(bucket.lastSeen) >= 10*time.Minute {
				delete(l.buckets, bucketKey)
			}
		}
		l.lastCleanup = now
	}

	bucket, exists := l.buckets[key]
	if !exists {
		bucket = &rateBucket{tokens: capacity, updated: now}
		l.buckets[key] = bucket
	}

	elapsed := now.Sub(bucket.updated).Seconds()
	bucket.tokens = math.Min(capacity, bucket.tokens+elapsed*refillPerSecond)
	bucket.updated = now
	bucket.lastSeen = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, 0
	}

	wait := time.Duration(math.Ceil((1 - bucket.tokens) / refillPerSecond * float64(time.Second)))
	return false, wait
}

func apiMiddleware(next http.Handler) http.Handler {
	limiter := newRateLimiter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if r.Method == http.MethodPost {
			var capacity, refillPerSecond float64
			switch r.URL.Path {
			case "/v1/auth/login":
				capacity = 5
				refillPerSecond = 5.0 / 60.0
			case "/v1/auth/register":
				capacity = 3
				refillPerSecond = 3.0 / 60.0
			case "/v1/me/password":
				capacity = 5
				refillPerSecond = 5.0 / 60.0
			}

			if capacity > 0 {
				key := r.URL.Path + "|" + clientIP(r)
				allowed, wait := limiter.allow(key, capacity, refillPerSecond)
				if !allowed {
					retrySeconds := int(math.Ceil(wait.Seconds()))
					if retrySeconds < 1 {
						retrySeconds = 1
					}
					w.Header().Set("Retry-After", fmt.Sprint(retrySeconds))
					writeJSON(w, http.StatusTooManyRequests, map[string]string{
						"error": "rate_limit_exceeded",
					})
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// clientIP uses the peer address and deliberately ignores untrusted forwarding headers.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
