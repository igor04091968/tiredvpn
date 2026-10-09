package gosthttp

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

type transportState struct {
	once    sync.Once
	initErr error
	plain   *http.Transport

	mu          sync.Mutex
	groups      map[routeKey]*connGroup
	events      chan struct{}
	connHook    func(*http.ClientConn)
	loopRunning bool
}

type connGroup struct {
	conns    []*pooledConn
	waiters  []*poolWaiter
	dialing  int
	protocol string
}

type poolWaiter struct {
	wake chan struct{}
}

type pooledConn struct {
	client    *http.ClientConn
	netConn   net.Conn
	tlsState  *gosttls.ConnectionState
	protocol  string
	idleSince time.Time
	uses      uint64
	hooked    bool
}

type acquiredConn struct {
	conn     *pooledConn
	reused   bool
	wasIdle  bool
	idleTime time.Duration
}

func (t *Transport) acquireConn(ctx context.Context, route dialRoute) (acquiredConn, error) {
	state := &t.state
	state.mu.Lock()
	group := state.groups[route.key]
	if group == nil {
		group = new(connGroup)
		state.groups[route.key] = group
	}
	// Do not allocate a waiter on the normal warmed-up path. New requests may
	// bypass the queue only when it is empty, preserving FIFO for contended
	// routes.
	if len(group.waiters) == 0 {
		if acquired, ok := t.reserveExistingLocked(group); ok {
			t.ensurePoolLoopLocked()
			state.mu.Unlock()
			return acquired, nil
		}
		if t.canDialLocked(group) {
			group.dialing++
			t.ensurePoolLoopLocked()
			state.mu.Unlock()
			return t.finishDial(ctx, route)
		}
	}

	waiter := &poolWaiter{wake: make(chan struct{}, 1)}
	group.waiters = append(group.waiters, waiter)
	t.updateStateHooksLocked(group)
	t.ensurePoolLoopLocked()
	state.mu.Unlock()

	for {
		state.mu.Lock()
		group = state.groups[route.key]
		if group == nil {
			group = &connGroup{waiters: []*poolWaiter{waiter}}
			state.groups[route.key] = group
		}
		isHead := len(group.waiters) != 0 && group.waiters[0] == waiter
		if isHead {
			if acquired, ok := t.reserveExistingLocked(group); ok {
				group.waiters = group.waiters[1:]
				t.updateStateHooksLocked(group)
				notifyHeadLocked(group)
				state.mu.Unlock()
				return acquired, nil
			}
			if t.canDialLocked(group) {
				group.dialing++
				group.waiters = group.waiters[1:]
				t.updateStateHooksLocked(group)
				notifyHeadLocked(group)
				state.mu.Unlock()
				return t.finishDial(ctx, route)
			}
		}
		state.mu.Unlock()

		select {
		case <-ctx.Done():
			state.mu.Lock()
			if group := state.groups[route.key]; group != nil {
				removeWaiterLocked(group, waiter)
				t.updateStateHooksLocked(group)
				notifyHeadLocked(group)
			}
			state.mu.Unlock()
			t.signalPoolEvent()
			return acquiredConn{}, ctx.Err()
		case <-waiter.wake:
		}
	}
}

func (t *Transport) finishDial(ctx context.Context, route dialRoute) (acquiredConn, error) {
	conn, err := t.dialClientConn(ctx, route)
	state := &t.state
	state.mu.Lock()
	group := state.groups[route.key]
	if group == nil {
		group = new(connGroup)
		state.groups[route.key] = group
	}
	group.dialing--
	if err == nil && conn != nil {
		group.conns = append(group.conns, conn)
		if group.protocol == "" {
			group.protocol = conn.protocol
		}
	}
	t.updateStateHooksLocked(group)
	notifyHeadLocked(group)
	t.ensurePoolLoopLocked()
	state.mu.Unlock()
	t.signalPoolEvent()
	if err != nil {
		return acquiredConn{}, err
	}
	return acquiredConn{conn: conn}, nil
}

func (t *Transport) reserveExistingLocked(group *connGroup) (acquiredConn, bool) {
	now := time.Now()
	for _, conn := range group.conns {
		if conn.client.Err() != nil {
			continue
		}
		inFlight := conn.client.InFlight()
		wasIdle := inFlight == 0
		idleTime := time.Duration(0)
		if wasIdle && !conn.idleSince.IsZero() {
			idleTime = now.Sub(conn.idleSince)
		}
		if err := conn.client.Reserve(); err != nil {
			continue
		}
		reused := conn.uses != 0
		conn.uses++
		conn.idleSince = time.Time{}
		return acquiredConn{
			conn:     conn,
			reused:   reused,
			wasIdle:  wasIdle,
			idleTime: idleTime,
		}, true
	}
	return acquiredConn{}, false
}

func (t *Transport) canDialLocked(group *connGroup) bool {
	live := 0
	for _, conn := range group.conns {
		if conn.client.Err() == nil {
			live++
		}
	}
	if t.MaxConnsPerHost > 0 && live+group.dialing >= t.MaxConnsPerHost {
		return false
	}
	if live == 0 && group.dialing == 0 {
		return true
	}
	// Until the first ALPN result is known, keep the initial connection
	// establishment single-flight.
	if group.protocol == "" {
		return false
	}
	if group.protocol == "h2" && t.HTTP2 != nil && t.HTTP2.StrictMaxConcurrentRequests {
		return false
	}
	return true
}

func removeWaiterLocked(group *connGroup, target *poolWaiter) {
	for index, waiter := range group.waiters {
		if waiter != target {
			continue
		}
		copy(group.waiters[index:], group.waiters[index+1:])
		group.waiters[len(group.waiters)-1] = nil
		group.waiters = group.waiters[:len(group.waiters)-1]
		return
	}
}

func notifyHeadLocked(group *connGroup) {
	if len(group.waiters) == 0 {
		return
	}
	select {
	case group.waiters[0].wake <- struct{}{}:
	default:
	}
}

func (t *Transport) updateStateHooksLocked(group *connGroup) {
	for _, conn := range group.conns {
		// HTTP/1 response bodies release their single slot asynchronously, and
		// ClientConn's hook is cheaper than another body wrapper there. HTTP/2
		// uses a body notification on the uncontended path and enables the hook
		// only while a waiter needs SETTINGS/GOAWAY/stream completion events.
		wantHook := conn.protocol == "http/1.1" || len(group.waiters) != 0
		if conn.hooked == wantHook {
			continue
		}
		conn.hooked = wantHook
		if wantHook {
			conn.client.SetStateHook(t.state.connHook)
		} else {
			conn.client.SetStateHook(nil)
		}
	}
}

func disableStateHook(conn *pooledConn) {
	if !conn.hooked {
		return
	}
	conn.hooked = false
	conn.client.SetStateHook(nil)
}

func (t *Transport) signalPoolEvent() {
	events := t.state.events
	if events == nil {
		return
	}
	select {
	case events <- struct{}{}:
	default:
	}
}

func (t *Transport) ensurePoolLoopLocked() {
	if t.state.loopRunning {
		return
	}
	t.state.loopRunning = true
	go t.poolLoop()
}

func (t *Transport) poolLoop() {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			stopPoolTimer(timer)
		}
	}()
	for {
		state := &t.state
		now := time.Now()
		state.mu.Lock()
		toClose := t.maintainPoolLocked(now)
		for _, group := range state.groups {
			notifyHeadLocked(group)
		}
		nextWake, keepRunning := t.nextPoolWakeLocked(now)
		if !keepRunning {
			state.loopRunning = false
		}
		state.mu.Unlock()

		for _, conn := range toClose {
			_ = conn.client.Close()
		}
		if !keepRunning {
			return
		}

		if nextWake.IsZero() {
			<-state.events
			continue
		}
		delay := time.Until(nextWake)
		if delay <= 0 {
			continue
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-state.events:
			stopPoolTimer(timer)
		case <-timer.C:
		}
	}
}

func stopPoolTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (t *Transport) maintainPoolLocked(now time.Time) []*pooledConn {
	state := &t.state
	var toClose []*pooledConn

	// The common event only changes an active connection to idle. Compact each
	// group in place so that this path performs no map, slice, or sort
	// allocations.
	for key, group := range state.groups {
		kept := group.conns[:0]
		for _, conn := range group.conns {
			if conn.client.Err() != nil {
				disableStateHook(conn)
				toClose = append(toClose, conn)
				continue
			}
			if conn.client.InFlight() != 0 {
				conn.idleSince = time.Time{}
				kept = append(kept, conn)
				continue
			}
			if conn.idleSince.IsZero() {
				conn.idleSince = now
			}
			if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 ||
				(t.IdleConnTimeout > 0 && !now.Before(conn.idleSince.Add(t.IdleConnTimeout))) {
				disableStateHook(conn)
				toClose = append(toClose, conn)
				continue
			}
			kept = append(kept, conn)
		}
		group.conns = kept
		if len(group.conns) == 0 && len(group.waiters) == 0 && group.dialing == 0 {
			delete(state.groups, key)
		}
	}

	perHostLimit := t.MaxIdleConnsPerHost
	if perHostLimit == 0 {
		perHostLimit = http.DefaultMaxIdleConnsPerHost
	}
	if perHostLimit >= 0 {
		for _, group := range state.groups {
			for excess := idleConnCount(group) - perHostLimit; excess > 0; excess-- {
				index := oldestIdleConnIndex(group)
				if index < 0 {
					break
				}
				conn := removeConnAt(group, index)
				disableStateHook(conn)
				toClose = append(toClose, conn)
			}
		}
	}

	if t.MaxIdleConns > 0 {
		for total := totalIdleConnCount(state.groups); total > t.MaxIdleConns; total-- {
			group, index := oldestIdleConn(state.groups)
			if group == nil {
				break
			}
			conn := removeConnAt(group, index)
			disableStateHook(conn)
			toClose = append(toClose, conn)
		}
	}

	for key, group := range state.groups {
		if len(group.conns) == 0 && len(group.waiters) == 0 && group.dialing == 0 {
			delete(state.groups, key)
		}
	}
	return toClose
}

func idleConnCount(group *connGroup) int {
	count := 0
	for _, conn := range group.conns {
		if !conn.idleSince.IsZero() && conn.client.InFlight() == 0 {
			count++
		}
	}
	return count
}

func totalIdleConnCount(groups map[routeKey]*connGroup) int {
	total := 0
	for _, group := range groups {
		total += idleConnCount(group)
	}
	return total
}

func oldestIdleConnIndex(group *connGroup) int {
	oldest := -1
	for index, conn := range group.conns {
		if conn.idleSince.IsZero() || conn.client.InFlight() != 0 {
			continue
		}
		if oldest < 0 || conn.idleSince.Before(group.conns[oldest].idleSince) {
			oldest = index
		}
	}
	return oldest
}

func oldestIdleConn(groups map[routeKey]*connGroup) (*connGroup, int) {
	var oldestGroup *connGroup
	oldestIndex := -1
	for _, group := range groups {
		index := oldestIdleConnIndex(group)
		if index < 0 {
			continue
		}
		if oldestGroup == nil || group.conns[index].idleSince.Before(oldestGroup.conns[oldestIndex].idleSince) {
			oldestGroup = group
			oldestIndex = index
		}
	}
	return oldestGroup, oldestIndex
}

func removeConnAt(group *connGroup, index int) *pooledConn {
	conn := group.conns[index]
	copy(group.conns[index:], group.conns[index+1:])
	last := len(group.conns) - 1
	group.conns[last] = nil
	group.conns = group.conns[:last]
	return conn
}

func (t *Transport) nextPoolWakeLocked(now time.Time) (time.Time, bool) {
	var next time.Time
	keepRunning := false
	for _, group := range t.state.groups {
		if len(group.conns) != 0 || len(group.waiters) != 0 || group.dialing != 0 {
			keepRunning = true
		}
		if t.IdleConnTimeout <= 0 {
			continue
		}
		for _, conn := range group.conns {
			if conn.idleSince.IsZero() || conn.client.InFlight() != 0 {
				continue
			}
			deadline := conn.idleSince.Add(t.IdleConnTimeout)
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}
	}
	return next, keepRunning
}

func (t *Transport) discardConn(target *pooledConn) {
	state := &t.state
	state.mu.Lock()
	for key, group := range state.groups {
		kept := group.conns[:0]
		for _, conn := range group.conns {
			if conn != target {
				kept = append(kept, conn)
			}
		}
		group.conns = kept
		t.updateStateHooksLocked(group)
		notifyHeadLocked(group)
		if len(group.conns) == 0 && len(group.waiters) == 0 && group.dialing == 0 {
			delete(state.groups, key)
		}
	}
	disableStateHook(target)
	state.mu.Unlock()
	_ = target.client.Close()
	t.signalPoolEvent()
}

// CloseIdleConnections closes all currently idle HTTP and HTTPS connections.
func (t *Transport) CloseIdleConnections() {
	if err := t.initialize(); err != nil {
		return
	}
	t.state.plain.CloseIdleConnections()

	state := &t.state
	state.mu.Lock()
	var toClose []*pooledConn
	for key, group := range state.groups {
		kept := group.conns[:0]
		for _, conn := range group.conns {
			if conn.client.InFlight() == 0 {
				disableStateHook(conn)
				toClose = append(toClose, conn)
				continue
			}
			kept = append(kept, conn)
		}
		group.conns = kept
		t.updateStateHooksLocked(group)
		notifyHeadLocked(group)
		if len(group.conns) == 0 && len(group.waiters) == 0 && group.dialing == 0 {
			delete(state.groups, key)
		}
	}
	state.mu.Unlock()
	for _, conn := range toClose {
		_ = conn.client.Close()
	}
	t.signalPoolEvent()
}
