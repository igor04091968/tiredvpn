package server

import (
	"container/list"
	"context"
	"sync"
)

// gostHandshakeLimiter is a FIFO limiter for the CPU-heavy part of GOST TLS.
// It bounds handshakes independently from the shared TCP admission semaphore.
type gostHandshakeLimiter struct {
	mu      sync.Mutex
	limit   int
	active  int
	queue   list.List
	metrics *Metrics
}

type gostHandshakeWaiter struct {
	ready   chan struct{}
	elem    *list.Element
	granted bool
}

func newGOSTHandshakeLimiter(limit int) *gostHandshakeLimiter {
	if limit <= 0 {
		panic("GOST handshake limiter requires a positive limit")
	}
	return &gostHandshakeLimiter{limit: limit}
}

func (l *gostHandshakeLimiter) setMetrics(m *Metrics) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.metrics = m
	l.mu.Unlock()
}

func (l *gostHandshakeLimiter) addActiveLocked(delta int64) {
	if l.metrics != nil {
		l.metrics.AddGOSTHandshakeActive(delta)
	}
}

func (l *gostHandshakeLimiter) addWaitingLocked(delta int64) {
	if l.metrics != nil {
		l.metrics.AddGOSTHandshakeWaiting(delta)
	}
}

func (l *gostHandshakeLimiter) acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	if l.active < l.limit && l.queue.Len() == 0 {
		l.active++
		l.addActiveLocked(1)
		l.mu.Unlock()
		return nil
	}
	w := &gostHandshakeWaiter{ready: make(chan struct{})}
	w.elem = l.queue.PushBack(w)
	l.addWaitingLocked(1)
	l.mu.Unlock()

	select {
	case <-w.ready:
		return nil
	case <-ctx.Done():
		l.mu.Lock()
		if w.granted {
			l.mu.Unlock()
			return nil
		}
		l.queue.Remove(w.elem)
		w.elem = nil
		l.addWaitingLocked(-1)
		l.mu.Unlock()
		return ctx.Err()
	}
}

func (l *gostHandshakeLimiter) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.active <= 0 {
		l.mu.Unlock()
		panic("release of unacquired GOST handshake slot")
	}
	l.active--
	l.addActiveLocked(-1)
	if front := l.queue.Front(); front != nil {
		w := front.Value.(*gostHandshakeWaiter)
		l.queue.Remove(front)
		w.elem = nil
		w.granted = true
		l.addWaitingLocked(-1)
		l.active++
		l.addActiveLocked(1)
		close(w.ready)
	}
	l.mu.Unlock()
}

func (l *gostHandshakeLimiter) counts() (active, waiting int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active, l.queue.Len()
}
