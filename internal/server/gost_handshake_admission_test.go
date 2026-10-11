package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

func TestNewGOSTHandshakeLimiterDefaultAndOverride(t *testing.T) {
	limiter, limit, err := newGOSTHandshakeLimiterFromConfig(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if limit != defaultMaxConcurrentGOSTHandshakes || limiter.limit != defaultMaxConcurrentGOSTHandshakes {
		t.Fatalf("default GOST handshake limit=%d/%d, want %d", limit, limiter.limit, defaultMaxConcurrentGOSTHandshakes)
	}
	limiter, limit, err = newGOSTHandshakeLimiterFromConfig(&Config{GOSTMaxHandshakes: 19})
	if err != nil {
		t.Fatal(err)
	}
	if limit != 19 || limiter.limit != 19 {
		t.Fatalf("configured GOST handshake limit=%d/%d, want 19", limit, limiter.limit)
	}
	if _, _, err := newGOSTHandshakeLimiterFromConfig(&Config{GOSTMaxHandshakes: -1}); err == nil {
		t.Fatal("negative GOST handshake limit was accepted")
	}
}

func TestGOSTHandshakeLimiterFIFOAndCancellation(t *testing.T) {
	limiter := newGOSTHandshakeLimiter(1)
	if err := limiter.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	release := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	done := make(chan int, 3)
	for i := 0; i < 3; i++ {
		i := i
		go func() {
			if err := limiter.acquire(context.Background()); err != nil {
				t.Errorf("waiter %d acquire: %v", i, err)
				return
			}
			close(started[i])
			<-release[i]
			limiter.release()
			done <- i
		}()
		waitForGOSTHandshakeCounts(t, limiter, 1, i+1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := limiter.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late waiter error=%v, want deadline exceeded", err)
	}
	waitForGOSTHandshakeCounts(t, limiter, 1, 3)
	limiter.release()
	for i := 0; i < 3; i++ {
		select {
		case <-started[i]:
		case <-time.After(time.Second):
			t.Fatalf("FIFO waiter %d was not granted", i)
		}
		for later := i + 1; later < 3; later++ {
			select {
			case <-started[later]:
				t.Fatalf("waiter %d was granted before earlier waiter %d", later, i)
			default:
			}
		}
		close(release[i])
		select {
		case got := <-done:
			if got != i {
				t.Fatalf("completed waiter=%d, want FIFO waiter %d", got, i)
			}
		case <-time.After(time.Second):
			t.Fatalf("FIFO waiter %d did not release", i)
		}
	}
	if active, waiting := limiter.counts(); active != 0 || waiting != 0 {
		t.Fatalf("final limiter counts active=%d waiting=%d, want 0/0", active, waiting)
	}
}

func TestGOSTHandshakeWaitTimeoutReleasesSharedAdmissionSlot(t *testing.T) {
	resetAdmission(t)
	initAdmissionControl(&Config{MaxConcurrentConns: 1})
	admissionDone := make(chan struct{}, 1)
	onHandlerDone = func(uint64, time.Time) { admissionDone <- struct{}{} }
	limiter := newGOSTHandshakeLimiter(1)
	if err := limiter.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := &serverContext{
		cfg:                  &Config{},
		gostTLSConfig:        gosttls.GOSTConfig(&gosttls.Config{}),
		gostHandshakeLimiter: limiter,
		metrics:              NewMetrics(nil),
	}
	client, serverConn := net.Pipe()
	done := make(chan struct{})
	accepted := acceptConnectionHandler(serverConn, ctx, 9901, func(conn net.Conn, srvCtx *serverContext, id uint64) {
		handleGOSTTLSConnectionWithTimeout(conn, srvCtx, id, 35*time.Millisecond)
		close(done)
	})
	if !accepted {
		t.Fatal("test connection was not admitted")
	}
	defer client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("queued GOST handler did not time out")
	}
	select {
	case <-admissionDone:
	case <-time.After(time.Second):
		t.Fatal("shared admission handler did not finish after GOST wait timeout")
	}
	if got := len(admissionSem); got != 0 {
		t.Fatalf("shared admission slot after GOST wait timeout=%d, want 0", got)
	}
	if active, waiting := limiter.counts(); active != 1 || waiting != 0 {
		t.Fatalf("limiter counts after timed-out waiter: active=%d waiting=%d", active, waiting)
	}
	if got := atomic.LoadInt64(&ctx.metrics.activeConnections); got != 0 {
		t.Fatalf("active connections after timed-out waiter=%d, want 0", got)
	}
	limiter.release()
	if active, waiting := limiter.counts(); active != 0 || waiting != 0 {
		t.Fatalf("limiter counts after releasing blocker=%d/%d, want 0/0", active, waiting)
	}
}

func TestGOSTHandshakeLimiterMetrics(t *testing.T) {
	metrics := NewMetrics(nil)
	limiter := newGOSTHandshakeLimiter(1)
	limiter.setMetrics(metrics)
	if err := limiter.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	go func() { queued <- limiter.acquire(ctx) }()
	waitForGOSTHandshakeCounts(t, limiter, 1, 1)
	if err := <-queued; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter result=%v, want deadline exceeded", err)
	}
	body := renderMetrics(t, metrics)
	if !strings.Contains(body, "tiredvpn_gost_handshakes_active 1") || !strings.Contains(body, "tiredvpn_gost_handshakes_waiting 0") {
		t.Fatalf("GOST metrics do not reflect active/waiting slots:\n%s", body)
	}
	limiter.release()
	body = renderMetrics(t, metrics)
	if !strings.Contains(body, "tiredvpn_gost_handshakes_active 0") || !strings.Contains(body, "tiredvpn_gost_handshakes_waiting 0") {
		t.Fatalf("GOST metrics did not return to zero:\n%s", body)
	}
}

func TestGOSTHandshakeFailureReleasesCryptoSlot(t *testing.T) {
	limiter := newGOSTHandshakeLimiter(1)
	want := errors.New("simulated TLS handshake failure")
	if err := performGOSTHandshake(limiter, time.Second, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("handshake error=%v, want %v", err, want)
	}
	if active, waiting := limiter.counts(); active != 0 || waiting != 0 {
		t.Fatalf("limiter counts after failed handshake=%d/%d, want 0/0", active, waiting)
	}
}

func waitForGOSTHandshakeCounts(t *testing.T, limiter *gostHandshakeLimiter, wantActive, wantWaiting int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		active, waiting := limiter.counts()
		if active == wantActive && waiting == wantWaiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	active, waiting := limiter.counts()
	t.Fatalf("limiter counts active=%d waiting=%d, want %d/%d", active, waiting, wantActive, wantWaiting)
}
