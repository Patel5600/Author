package relay

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// clientRecord tracks timestamps of requests for a client IP.
type clientRecord struct {
	timestamps []time.Time
}

// RateLimiter implements a sliding window in-memory rate limiter per IP.
type RateLimiter struct {
	mu      sync.Mutex
	records map[string]*clientRecord
	limit   int
	window  time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		records: make(map[string]*clientRecord),
		limit:   limit,
		window:  window,
	}
	go rl.cleanupWorker()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	rec, exists := rl.records[ip]
	if !exists {
		rec = &clientRecord{}
		rl.records[ip] = rec
	}

	// Filter out expired timestamps
	valid := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	rec.timestamps = valid

	if len(rec.timestamps) >= rl.limit {
		return false
	}

	rec.timestamps = append(rec.timestamps, now)
	return true
}

func (rl *RateLimiter) cleanupWorker() {
	ticker := time.NewTicker(rl.window * 2)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for ip, rec := range rl.records {
			var valid []time.Time
			for _, ts := range rec.timestamps {
				if ts.After(cutoff) {
					valid = append(valid, ts)
				}
			}
			if len(valid) == 0 {
				delete(rl.records, ip)
			} else {
				rec.timestamps = valid
			}
		}
		rl.mu.Unlock()
	}
}

// GetClientIP extracts real client IP handling common reverse proxy headers.
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LoggingMiddleware logs incoming requests with status code and duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriterInterceptor{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		log.Printf("[%s] %s %s %d (%v)", GetClientIP(r), r.Method, r.URL.Path, rw.statusCode, duration)
	})
}

// CORSMiddleware adds basic CORS headers for web/app clients.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterInterceptor) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterInterceptor) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriterInterceptor) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
