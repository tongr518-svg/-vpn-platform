package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLoginRateLimit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := apiMiddleware(next)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		req.RemoteAddr = "192.0.2.10:12345"
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("第 %d 次请求应通过，得到状态码 %d", i+1, recorder.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("第 6 次请求应返回 429，得到状态码 %d", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("限流响应缺少 Retry-After")
	}
}

func TestAuthRateLimits(t *testing.T) {
	tests := []struct {
		path     string
		capacity int
	}{
		{path: "/v1/auth/login", capacity: 5},
		{path: "/v1/auth/register", capacity: 3},
		{path: "/v1/me/password", capacity: 5},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			handler := apiMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			for i := 0; i < test.capacity; i++ {
				req := httptest.NewRequest(http.MethodPost, test.path, nil)
				req.RemoteAddr = "192.0.2.20:12345"
				req.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(i+1))
				recorder := httptest.NewRecorder()

				handler.ServeHTTP(recorder, req)
				if recorder.Code != http.StatusNoContent {
					t.Fatalf("第 %d 次请求应通过，得到状态码 %d", i+1, recorder.Code)
				}
			}

			req := httptest.NewRequest(http.MethodPost, test.path, nil)
			req.RemoteAddr = "192.0.2.20:12345"
			req.Header.Set("X-Forwarded-For", "203.0.113.99")
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("超过初始额度后应返回 429，得到 %d", recorder.Code)
			}
			if recorder.Header().Get("Retry-After") == "" {
				t.Fatal("429 响应应包含 Retry-After")
			}
		})
	}
}

func TestRateLimiterDoesNotExceedCapacityConcurrently(t *testing.T) {
	const (
		capacity = 10
		requests = 100
	)

	limiter := newRateLimiter()
	var allowed atomic.Int64
	var wg sync.WaitGroup

	wg.Add(requests)
	for i := 0; i < requests; i++ {
		go func() {
			defer wg.Done()

			ok, _ := limiter.allow("same-client", capacity, 1e-9)
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != capacity {
		t.Fatalf("并发请求通过数应为 %d，实际为 %d", capacity, got)
	}
}
