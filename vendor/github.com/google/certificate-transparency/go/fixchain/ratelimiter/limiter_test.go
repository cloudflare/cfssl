package ratelimiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testlimits = []int{1, 10, 50, 100, 1000}

func checkTicker(t *testing.T, tick *time.Ticker, count *int64, i, limit int) {
	for range tick.C {
		// Allow a count up to slightly more than the limit as scheduling of
		// goroutine vs the main thread could cause this check to not be
		// run quite in time for limit.
		allowed := int(float64(limit)*1.05) + 1
		v := atomic.LoadInt64(count)
		if v > int64(allowed) {
			t.Errorf("#%d: Too many operations per second. Expected ~%d, got %d", i, limit, v)
		}
		atomic.StoreInt64(count, 0)
	}
}

func TestRateLimiterSingleThreaded(t *testing.T) {
	for i, limit := range testlimits {
		l := NewLimiter(limit)
		count := int64(0)
		tick := time.NewTicker(time.Second)
		go checkTicker(t, tick, &count, i, limit)

		for i := 0; i < 3*limit; i++ {
			l.Wait()
			atomic.AddInt64(&count, 1)
		}
		tick.Stop()
	}
}

func TestRateLimiterGoroutines(t *testing.T) {
	for i, limit := range testlimits {
		l := NewLimiter(limit)
		count := int64(0)
		tick := time.NewTicker(time.Second)
		go checkTicker(t, tick, &count, i, limit)

		var wg sync.WaitGroup
		for i := 0; i < 3*limit; i++ {
			wg.Add(1)
			go func() {
				l.Wait()
				atomic.AddInt64(&count, 1)
				wg.Done()
			}()
		}
		wg.Wait()
		tick.Stop()
	}
}
