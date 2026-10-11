//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/xtaci/smux"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	gostx509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

const (
	gostHandshakeLoadEnv       = "TIREDVPN_RUN_GOST_HANDSHAKE_LOAD"
	gostHandshakeLoadHelperEnv = "TIREDVPN_GOST_HANDSHAKE_LOAD_HELPER"
)

type gostLoadClientResult struct {
	HandshakeNanos []int64  `json:"handshake_nanos"`
	Failures       []string `json:"failures,omitempty"`
}

// TestGOSTHandshakeLoad is an opt-in loopback load test. The test process runs
// only the server, while a child test process generates real GOST TLS 1.3
// ClientHellos and handshakes. This keeps server CPU and RSS measurements
// separate from client-side cryptography.
//
// Run with TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 go test ./internal/server -run
// '^TestGOSTHandshakeLoad$' -count=1 -v. Set
// TIREDVPN_GOST_HANDSHAKE_LOAD_MAX to raise the default concurrency ceiling of
// 256, up to the server's default admission limit of 4096.
func TestGOSTHandshakeLoad(t *testing.T) {
	if os.Getenv(gostHandshakeLoadEnv) != "1" {
		t.Skip("set " + gostHandshakeLoadEnv + "=1 to run the GOST TLS handshake load test")
	}
	log.SetLevel(log.LevelWarn)
	defer log.SetLevel(log.LevelInfo)
	resetAdmission(t)
	initAdmissionControl(&Config{MaxConcurrentConns: defaultMaxConcurrentConns})

	cert := makeGOSTLoadCertificate(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx := &serverContext{
		cfg:           &Config{},
		gostTLSConfig: gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{cert}}),
		metrics:       NewMetrics(nil),
	}
	doneEvents := make(chan struct{}, defaultMaxConcurrentConns)
	onHandlerDone = func(uint64, time.Time) { doneEvents <- struct{}{} }
	go serveGOSTTLSListener(listener, ctx)

	maxConcurrency := 256
	if raw := os.Getenv("TIREDVPN_GOST_HANDSHAKE_LOAD_MAX"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > defaultMaxConcurrentConns {
			t.Fatalf("TIREDVPN_GOST_HANDSHAKE_LOAD_MAX must be 1..%d", defaultMaxConcurrentConns)
		}
		maxConcurrency = value
	}
	limits := []struct {
		name  string
		limit int
	}{{"default128", defaultMaxConcurrentGOSTHandshakes}}
	levels := []int{1, 8, 32, 128, 256, 512, 1024, 2048, defaultMaxConcurrentConns}
	if os.Getenv("TIREDVPN_GOST_HANDSHAKE_LOAD_COMPARE") == "1" {
		limits = []struct {
			name  string
			limit int
		}{{"128", 128}, {"256", 256}, {"512", 512}, {"1024", 1024}, {"uncapped", defaultMaxConcurrentConns}}
		levels = []int{1024, 2048, defaultMaxConcurrentConns}
	}
	for _, profile := range limits {
		ctx.gostHandshakeLimiter = newGOSTHandshakeLimiter(profile.limit)
		ctx.gostHandshakeLimiter.setMetrics(ctx.metrics)
		for _, concurrency := range levels {
			if concurrency > maxConcurrency {
				continue
			}
			t.Run(fmt.Sprintf("limit_%s/concurrency_%d", profile.name, concurrency), func(t *testing.T) {
				result, report := runGOSTLoadPhase(t, listener.Addr().String(), concurrency, ctx.metrics, ctx.gostHandshakeLimiter)
				if len(result.Failures) != 0 {
					t.Fatalf("%d/%d GOST handshakes failed; first: %s", len(result.Failures), concurrency, result.Failures[0])
				}
				if len(result.HandshakeNanos) != concurrency {
					t.Fatalf("completed %d handshakes, want %d", len(result.HandshakeNanos), concurrency)
				}
				t.Log(report)
				waitHandlerCompletions(t, doneEvents, concurrency)
				waitAdmissionEmpty(t)
			})
		}
	}
}

// TestGOSTHandshakeLoadClient runs only as a subprocess helper for the parent
// load test. Every connection completes a real TLS handshake and smux setup,
// then remains open briefly so the parent can sample peak server resources.
func TestGOSTHandshakeLoadClient(t *testing.T) {
	if os.Getenv(gostHandshakeLoadHelperEnv) != "1" {
		return
	}
	address := os.Getenv("TIREDVPN_GOST_HANDSHAKE_LOAD_ADDR")
	count, err := strconv.Atoi(os.Getenv("TIREDVPN_GOST_HANDSHAKE_LOAD_COUNT"))
	if err != nil || count < 1 {
		t.Fatalf("invalid helper connection count: %v", err)
	}

	result := gostLoadClientResult{HandshakeNanos: make([]int64, count)}
	result.Failures = make([]string, count)
	sessions := make([]*smux.Session, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp4", address, 10*time.Second)
			if err != nil {
				result.Failures[i] = fmt.Sprintf("dial: %v", err)
				return
			}
			_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
			client := gosttls.Client(conn, gosttls.GOSTConfig(&gosttls.Config{
				ServerName:         "load.test",
				InsecureSkipVerify: true, // The benchmark uses an ephemeral test certificate.
			}))
			started := time.Now()
			if err := client.Handshake(); err != nil {
				result.Failures[i] = fmt.Sprintf("GOST TLS handshake: %v", err)
				_ = conn.Close()
				return
			}
			state := client.ConnectionState()
			if state.Version != gosttls.VersionTLS13 || !isGOSTSuiteServer(state.CipherSuite) {
				result.Failures[i] = fmt.Sprintf("unexpected negotiated profile: version=%x suite=%04x", state.Version, state.CipherSuite)
				_ = conn.Close()
				return
			}
			result.HandshakeNanos[i] = time.Since(started).Nanoseconds()
			if err := protocol.WriteDispatch(client, protocol.TypeMux); err != nil {
				result.Failures[i] = fmt.Sprintf("mux dispatch: %v", err)
				_ = conn.Close()
				return
			}
			session, err := smux.Client(client, smux.DefaultConfig())
			if err != nil {
				result.Failures[i] = fmt.Sprintf("smux setup: %v", err)
				_ = conn.Close()
				return
			}
			sessions[i] = session
		}(i)
	}
	wg.Wait()
	time.Sleep(400 * time.Millisecond)
	for _, session := range sessions {
		if session != nil {
			_ = session.Close()
		}
	}
	successful := result.HandshakeNanos[:0]
	for _, elapsed := range result.HandshakeNanos {
		if elapsed > 0 {
			successful = append(successful, elapsed)
		}
	}
	result.HandshakeNanos = successful
	failures := result.Failures[:0]
	for _, failure := range result.Failures {
		if failure != "" {
			failures = append(failures, failure)
		}
	}
	result.Failures = failures
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(encoded))
}

func runGOSTLoadPhase(t *testing.T, address string, concurrency int, metrics *Metrics, limiter *gostHandshakeLimiter) (gostLoadClientResult, string) {
	t.Helper()
	runtime.GC()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGOSTHandshakeLoadClient$")
	cmd.Env = append(os.Environ(),
		gostHandshakeLoadHelperEnv+"=1",
		"TIREDVPN_GOST_HANDSHAKE_LOAD_ADDR="+address,
		"TIREDVPN_GOST_HANDSHAKE_LOAD_COUNT="+strconv.Itoa(concurrency),
	)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output

	userBefore, sysBefore := processCPUMicros()
	rssBefore := processRSSBytes()
	goroutinesBefore := runtime.NumGoroutine()
	activeBefore := atomic.LoadInt64(&metrics.activeConnections)
	rejectedBefore := atomic.LoadInt64(&metrics.admissionRejected)
	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start GOST client helper: %v", err)
	}
	var peakRSS uint64
	var peakGoroutines, peakActive, peakGOSTHandshakes int
	samplingDone := make(chan struct{})
	samplerExited := make(chan struct{})
	go func() {
		defer close(samplerExited)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-samplingDone:
				return
			case <-ticker.C:
				if rss := processRSSBytes(); rss > peakRSS {
					peakRSS = rss
				}
				if count := runtime.NumGoroutine(); count > peakGoroutines {
					peakGoroutines = count
				}
				if count := int(atomic.LoadInt64(&metrics.activeConnections)); count > peakActive {
					peakActive = count
				}
				count, _ := limiter.counts()
				if count > peakGOSTHandshakes {
					peakGOSTHandshakes = count
				}
			}
		}
	}()
	err := cmd.Wait()
	close(samplingDone)
	<-samplerExited
	elapsed := time.Since(started)
	userAfter, sysAfter := processCPUMicros()
	if err != nil {
		t.Fatalf("GOST client helper failed: %v\n%s", err, output.String())
	}
	var result gostLoadClientResult
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "{\"handshake_nanos\"") {
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				t.Fatalf("decode helper result: %v\n%s", err, line)
			}
			break
		}
	}
	if result.HandshakeNanos == nil {
		t.Fatalf("GOST client helper returned no result\n%s", output.String())
	}
	sort.Slice(result.HandshakeNanos, func(i, j int) bool { return result.HandshakeNanos[i] < result.HandshakeNanos[j] })
	if len(result.HandshakeNanos) == 0 {
		t.Fatalf("no GOST handshakes succeeded\n%s", output.String())
	}
	rejected := atomic.LoadInt64(&metrics.admissionRejected) - rejectedBefore
	if peakRSS < rssBefore {
		peakRSS = rssBefore
	}
	if peakGoroutines < goroutinesBefore {
		peakGoroutines = goroutinesBefore
	}
	if peakActive < int(activeBefore) {
		peakActive = int(activeBefore)
	}
	percentile := func(p int) time.Duration {
		return time.Duration(result.HandshakeNanos[(len(result.HandshakeNanos)-1)*p/100])
	}
	formatBytes := func(n uint64) string { return fmt.Sprintf("%.1fMiB", float64(n)/(1024*1024)) }
	limitLabel := strconv.Itoa(limiter.limit)
	if limiter.limit == defaultMaxConcurrentConns {
		limitLabel += "-tcp-cap"
	}
	if peakGOSTHandshakes > limiter.limit {
		t.Fatalf("observed %d simultaneous GOST handshakes, configured limit is %d", peakGOSTHandshakes, limiter.limit)
	}
	report := fmt.Sprintf("GOST load: limit=%s concurrency=%d success=%d/%d rejected=%d elapsed=%s throughput=%.1f/s handshake_ms[min/p50/p90/p99/max]=%.2f/%.2f/%.2f/%.2f/%.2f server_cpu_user/sys=%d/%dms rss_baseline/peak/delta=%s/%s/%s server_goroutines_baseline/peak/delta=%d/%d/%d active_connections_peak=%d gost_handshakes_peak=%d",
		limitLabel, concurrency, len(result.HandshakeNanos), len(result.HandshakeNanos)+len(result.Failures), rejected, elapsed,
		float64(concurrency)/elapsed.Seconds(), time.Duration(result.HandshakeNanos[0]).Seconds()*1000,
		percentile(50).Seconds()*1000, percentile(90).Seconds()*1000, percentile(99).Seconds()*1000,
		time.Duration(result.HandshakeNanos[len(result.HandshakeNanos)-1]).Seconds()*1000,
		(userAfter-userBefore)/1000, (sysAfter-sysBefore)/1000, formatBytes(rssBefore), formatBytes(peakRSS), formatBytes(peakRSS-rssBefore),
		goroutinesBefore, peakGoroutines, peakGoroutines-goroutinesBefore, peakActive, peakGOSTHandshakes)
	if rejected != 0 {
		t.Fatalf("admission rejected %d connections during GOST load phase", rejected)
	}
	return result, report
}

func makeGOSTLoadCertificate(t *testing.T) gosttls.Certificate {
	t.Helper()
	priv, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost341012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &gostx509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "load.test"}, DNSNames: []string{"load.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign,
		ExtKeyUsage: []gostx509.ExtKeyUsage{gostx509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := gostx509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := gostx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gosttls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func waitAdmissionEmpty(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(admissionSem) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(admissionSem); got != 0 {
		t.Fatalf("admission slots still held after GOST load phase: %d", got)
	}
}

func waitHandlerCompletions(t *testing.T, events <-chan struct{}, count int) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for completed := 0; completed < count; completed++ {
		select {
		case <-events:
		case <-deadline.C:
			t.Fatalf("only %d/%d GOST handlers completed", completed, count)
		}
	}
}

func processRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseUint(fields[1], 10, 64)
				return value * 1024
			}
		}
	}
	return 0
}

func processCPUMicros() (user, system int64) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, 0
	}
	return usage.Utime.Sec*1_000_000 + usage.Utime.Usec, usage.Stime.Sec*1_000_000 + usage.Stime.Usec
}
