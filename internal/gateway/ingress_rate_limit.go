package gateway

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

type fixedWindowCounter struct {
	windowID int64
	count    int
}

type fixedWindowLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	windowSec int64
	counters  map[string]fixedWindowCounter
	calls     int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	if window <= 0 {
		window = time.Minute
	}
	windowSec := int64(window / time.Second)
	if windowSec <= 0 {
		windowSec = 1
	}
	return &fixedWindowLimiter{
		limit:     limit,
		window:    window,
		windowSec: windowSec,
		counters:  make(map[string]fixedWindowCounter),
	}
}

func (l *fixedWindowLimiter) Allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "_"
	}

	windowID := now.Unix() / l.windowSec

	l.mu.Lock()
	defer l.mu.Unlock()

	rec := l.counters[key]
	if rec.windowID != windowID {
		rec.windowID = windowID
		rec.count = 0
	}
	if rec.count >= l.limit {
		return false
	}
	rec.count++
	l.counters[key] = rec

	l.calls++
	if l.calls%1024 == 0 {
		for counterKey, counter := range l.counters {
			if windowID-counter.windowID > 2 {
				delete(l.counters, counterKey)
			}
		}
	}

	return true
}

type IngressRateLimiter struct {
	window  time.Duration
	global  *fixedWindowLimiter
	byIP    *fixedWindowLimiter
	byRoute *fixedWindowLimiter
}

// OAuthRateLimiter applies per-IP rate limiting to OAuth endpoints.
type OAuthRateLimiter struct {
	window time.Duration
	byIP   *fixedWindowLimiter
}

func NewIngressRateLimiter(globalLimit, ipLimit, routeLimit int, window time.Duration) *IngressRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &IngressRateLimiter{
		window:  window,
		global:  newFixedWindowLimiter(globalLimit, window),
		byIP:    newFixedWindowLimiter(ipLimit, window),
		byRoute: newFixedWindowLimiter(routeLimit, window),
	}
}

func (l *IngressRateLimiter) GlobalMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		if l.global.Allow("global", time.Now().UTC()) {
			return c.Next()
		}
		c.Set("Retry-After", strconv.Itoa(int(l.window.Seconds())))
		return c.SendStatus(fiber.StatusTooManyRequests)
	}
}

func (l *IngressRateLimiter) IPMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		key := strings.TrimSpace(c.IP())
		if l.byIP.Allow(key, time.Now().UTC()) {
			return c.Next()
		}
		c.Set("Retry-After", strconv.Itoa(int(l.window.Seconds())))
		return c.SendStatus(fiber.StatusTooManyRequests)
	}
}

func (l *IngressRateLimiter) RouteMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		key := strings.TrimSpace(c.Params("route_id"))
		if key == "" {
			key = strings.TrimSpace(c.Path())
		}
		if l.byRoute.Allow(key, time.Now().UTC()) {
			return c.Next()
		}
		c.Set("Retry-After", strconv.Itoa(int(l.window.Seconds())))
		return c.SendStatus(fiber.StatusTooManyRequests)
	}
}

func NewOAuthRateLimiter(ipLimit int, window time.Duration) *OAuthRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &OAuthRateLimiter{
		window: window,
		byIP:   newFixedWindowLimiter(ipLimit, window),
	}
}

func (l *OAuthRateLimiter) Middleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		key := strings.TrimSpace(c.IP())
		if l.byIP.Allow(key, time.Now().UTC()) {
			return c.Next()
		}
		c.Set("Retry-After", strconv.Itoa(int(l.window.Seconds())))
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too_many_requests"})
	}
}
