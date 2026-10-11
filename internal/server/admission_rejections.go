package server

import (
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

const admissionRejectLogInterval = 10 * time.Second

type admissionRejectReporter struct {
	mu       sync.Mutex
	interval time.Duration
	active   bool
	dropped  uint64
	first    func(connID uint64, remote net.Addr, limit int)
	summary  func(count uint64)
}

func newAdmissionRejectReporter(interval time.Duration, first func(uint64, net.Addr, int), summary func(uint64)) *admissionRejectReporter {
	return &admissionRejectReporter{interval: interval, first: first, summary: summary}
}

func (r *admissionRejectReporter) reject(connID uint64, remote net.Addr, limit int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active {
		r.active = true
		r.first(connID, remote, limit)
		time.AfterFunc(r.interval, r.flush)
		return
	}
	r.dropped++
}

func (r *admissionRejectReporter) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dropped == 0 {
		r.active = false
		return
	}
	count := r.dropped
	r.dropped = 0
	r.summary(count)
	time.AfterFunc(r.interval, r.flush)
}

var admissionRejectLogs = newAdmissionRejectReporter(
	admissionRejectLogInterval,
	func(connID uint64, remote net.Addr, limit int) {
		log.Warn("Admission control: dropping connection %d from %v (limit %d reached)", connID, remote, limit)
	},
	func(count uint64) {
		log.Warn("Admission control: dropped %d additional connections in the last %s (limit reached)", count, admissionRejectLogInterval)
	},
)
