package server

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

// TestGOSTAdmissionStress is an opt-in loopback test for stalled handshakes.
// It opens the actual default admission capacity and holds clients without
// sending ClientHello bytes until the production 30-second deadline expires.
// Run with TIREDVPN_RUN_ADMISSION_STRESS=1; this intentionally takes ~32s.
func TestGOSTAdmissionStress(t *testing.T) {
	if os.Getenv("TIREDVPN_RUN_ADMISSION_STRESS") != "1" {
		t.Skip("set TIREDVPN_RUN_ADMISSION_STRESS=1 to run the 4096-connection, ~32s loopback test")
	}
	resetAdmission(t)
	initAdmissionControl(&Config{}) // default, 4096 concurrent connections

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx := &serverContext{
		cfg:           &Config{},
		gostTLSConfig: gosttls.GOSTConfig(&gosttls.Config{}),
		metrics:       NewMetrics(nil),
	}
	go serveGOSTTLSListener(listener, ctx)

	const admitted = defaultMaxConcurrentConns
	const overflow = 512
	clients := make([]net.Conn, 0, admitted+overflow)
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}()

	type releaseEvent struct {
		connID uint64
		at     time.Time
	}
	var mu sync.Mutex
	starts := make(map[uint64]time.Time, admitted)
	finished := make(chan releaseEvent, admitted)
	var fullSince, fullyReleasedAt time.Time
	onHandlerAdmitted = func(connID uint64, at time.Time) {
		mu.Lock()
		starts[connID] = at
		if len(admissionSem) == admitted {
			fullSince = at
		}
		mu.Unlock()
	}
	onHandlerDone = func(connID uint64, at time.Time) {
		if len(admissionSem) == 0 {
			mu.Lock()
			fullyReleasedAt = at
			mu.Unlock()
		}
		finished <- releaseEvent{connID: connID, at: at}
	}

	var before, atCapacity, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rssBefore := processRSS()
	started := time.Now()
	for i := 0; i < admitted; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial admitted connection %d/%d: %v", i+1, admitted, err)
		}
		clients = append(clients, conn)
	}

	waitUntil := time.Now().Add(10 * time.Second)
	for len(admissionSem) != admitted && time.Now().Before(waitUntil) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(admissionSem); got != admitted {
		t.Fatalf("occupied slots=%d, want %d", got, admitted)
	}
	runtime.ReadMemStats(&atCapacity)
	rssAtCapacity := processRSS()
	cpuBeforeBurst := processUserCPU()

	burstStart := time.Now()
	for i := 0; i < overflow; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial overflow connection %d/%d: %v", i+1, overflow, err)
		}
		clients = append(clients, conn)
	}
	burstDuration := time.Since(burstStart)
	for _, conn := range clients[admitted:] {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		_, err := conn.Read(b[:])
		if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("overflow read error=%v; want EOF or ECONNRESET (a read timeout is a test failure)", err)
		}
	}
	burstCPU := processUserCPU() - cpuBeforeBurst
	if got := runtimeMetricsAdmissionRejected(ctx.metrics); got != overflow {
		t.Fatalf("admission rejected metric=%d, want %d", got, overflow)
	}

	// Wait for each handler's completion event rather than sleeping a fixed
	// duration, so we can measure the full release time and slot hold durations.
	durations := make([]time.Duration, 0, admitted)
	completeBy := time.NewTimer(45 * time.Second)
	defer completeBy.Stop()
	for i := 0; i < admitted; i++ {
		select {
		case event := <-finished:
			mu.Lock()
			startedAt := starts[event.connID]
			mu.Unlock()
			if startedAt.IsZero() {
				t.Fatalf("missing admission timestamp for connection %d", event.connID)
			}
			durations = append(durations, event.at.Sub(startedAt))
		case <-completeBy.C:
			t.Fatalf("only %d/%d handlers completed by deadline", i, admitted)
		}
	}
	if got := len(admissionSem); got != 0 {
		t.Fatalf("occupied slots after all handler completion events=%d, want 0", got)
	}
	mu.Lock()
	fullDuration := fullyReleasedAt.Sub(fullSince)
	mu.Unlock()
	if fullSince.IsZero() || fullyReleasedAt.IsZero() {
		t.Fatal("failed to capture full-capacity and full-release timestamps")
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	runtime.GC()
	runtime.ReadMemStats(&after)
	rate := float64(overflow) / burstDuration.Seconds()
	t.Logf("admitted=%d overflow=%d overflow_rate=%.0f/s burst=%s full_capacity_hold=%s slot_hold_min=%s p50=%s p90=%s p99=%s max=%s rss_before=%s rss_at_capacity=%s heap_alloc_at_capacity_delta=%d heap_sys_at_capacity_delta=%d heap_alloc_after_delta=%d heap_sys_after_delta=%d burst_user_cpu_delta=%d us elapsed=%s",
		admitted, overflow, rate, burstDuration, fullDuration, durations[0], durations[len(durations)*50/100], durations[len(durations)*90/100], durations[len(durations)*99/100], durations[len(durations)-1], rssBefore, rssAtCapacity,
		int64(atCapacity.Alloc)-int64(before.Alloc), int64(atCapacity.Sys)-int64(before.Sys),
		int64(after.Alloc)-int64(before.Alloc), int64(after.Sys)-int64(before.Sys), burstCPU, time.Since(started))
}

func runtimeMetricsAdmissionRejected(m *Metrics) int64 {
	return atomic.LoadInt64(&m.admissionRejected)
}

func processRSS() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "unavailable"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			return line
		}
	}
	return "unavailable"
}

func processUserCPU() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return usage.Utime.Sec*1_000_000 + usage.Utime.Usec
}
