package server

import (
	"net"
	"testing"
	"time"
)

func TestAdmissionRejectReporterEmitsFirstAndSummary(t *testing.T) {
	type event struct {
		first  bool
		connID uint64
		count  uint64
		limit  int
		remote net.Addr
	}
	events := make(chan event, 2)
	reporter := newAdmissionRejectReporter(20*time.Millisecond,
		func(id uint64, remote net.Addr, limit int) {
			events <- event{first: true, connID: id, remote: remote, limit: limit}
		},
		func(count uint64) { events <- event{count: count} },
	)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	reporter.reject(7, addr, 4)
	for i := 0; i < 3; i++ {
		reporter.reject(uint64(8+i), addr, 4)
	}

	select {
	case got := <-events:
		if !got.first || got.connID != 7 || got.remote.String() != addr.String() || got.limit != 4 {
			t.Fatalf("first event=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first rejection was not reported immediately")
	}
	select {
	case got := <-events:
		if got.first || got.count != 3 {
			t.Fatalf("summary event=%+v, want count=3", got)
		}
	case <-time.After(time.Second):
		t.Fatal("suppressed rejections were not summarized")
	}
}
