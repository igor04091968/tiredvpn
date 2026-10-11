package server

import (
	"net"
	"os"
	"runtime"
	"strings"
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
		if _, err := conn.Read(b[:]); err == nil {
			t.Fatal("overflow connection remained open")
		}
	}
	burstCPU := processUserCPU() - cpuBeforeBurst

	// The actual GOST handler uses this fixed handshake deadline.
	time.Sleep(31 * time.Second)
	waitUntil = time.Now().Add(5 * time.Second)
	for len(admissionSem) != 0 && time.Now().Before(waitUntil) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(admissionSem); got != 0 {
		t.Fatalf("occupied slots after handshake deadline=%d, want 0", got)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	rate := float64(overflow) / burstDuration.Seconds()
	t.Logf("admitted=%d overflow=%d overflow_rate=%.0f/s burst=%s rss_before=%s rss_at_capacity=%s heap_alloc_at_capacity_delta=%d heap_sys_at_capacity_delta=%d heap_alloc_after_delta=%d heap_sys_after_delta=%d burst_user_cpu_delta=%d us elapsed=%s",
		admitted, overflow, rate, burstDuration, rssBefore, rssAtCapacity,
		int64(atCapacity.Alloc)-int64(before.Alloc), int64(atCapacity.Sys)-int64(before.Sys),
		int64(after.Alloc)-int64(before.Alloc), int64(after.Sys)-int64(before.Sys), burstCPU, time.Since(started))
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
