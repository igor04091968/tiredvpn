//go:build linux

package geneva

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// InjectorPacketMark is set via SO_MARK on the raw socket used to inject
// additional packets (fragments/duplicates). Exclude it from the NFQUEUE rule
// so injected packets don't re-enter the queue and loop:
//
//	iptables -I OUTPUT -p tcp -d <server-ip> -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num <N>
const InjectorPacketMark = 0x54495245 // "TIRE"

// Injector intercepts TCP packets via Linux NFQUEUE and applies Geneva
// strategies before releasing them to the kernel.
//
// It can serve one queue (outbound only) or two (outbound and inbound). The
// inbound queue is what the RST-filtering strategies need: a censor's forged
// RST arrives on INPUT, and dropping it there is the only way to keep a
// connection the censor tried to kill.
//
// Prerequisites:
//   - CAP_NET_ADMIN
//   - iptables rules with mark exclusion (see InjectorPacketMark):
//     iptables -I OUTPUT -p tcp -d <server-ip> -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num <N>
//     iptables -I INPUT  -p tcp -s <server-ip> -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num <N+1>
type Injector struct {
	strategies []*Strategy
	outQueue   uint16
	inQueue    uint16
	inEnabled  bool
	nfqOut     *nfqueue.Nfqueue
	nfqIn      *nfqueue.Nfqueue

	mu     sync.Mutex
	rawFd  int
	closed bool

	cancel context.CancelFunc
}

// NewInjector creates an outbound-only Injector for the given NFQUEUE number.
func NewInjector(queueNum uint16, strategies []*Strategy) *Injector {
	return &Injector{
		outQueue:   queueNum,
		strategies: strategies,
		rawFd:      -1,
	}
}

// NewInjectorDuplex creates an Injector serving an outbound queue and an inbound
// queue. Inbound strategies are applied to packets arriving on inQueue.
func NewInjectorDuplex(outQueue, inQueue uint16, strategies []*Strategy) *Injector {
	return &Injector{
		outQueue:   outQueue,
		inQueue:    inQueue,
		inEnabled:  true,
		strategies: strategies,
		rawFd:      -1,
	}
}

// Start opens the NFQUEUE(s) and begins processing packets.
// Returns an error immediately if CAP_NET_ADMIN is unavailable.
func (inj *Injector) Start(ctx context.Context) error {
	// Raw socket is needed to inject additional packets (fragments, duplicates,
	// delayed packets) when a strategy produces more than one output packet.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("geneva injector: raw socket failed (need CAP_NET_ADMIN): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("geneva injector: IP_HDRINCL: %w", err)
	}
	// Mark injected packets so the iptables NFQUEUE rules (which must use
	// ! --mark InjectorPacketMark) do not re-queue them, preventing an
	// infinite re-injection loop.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, InjectorPacketMark); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("geneva injector: SO_MARK: %w", err)
	}
	inj.mu.Lock()
	inj.rawFd = fd
	inj.mu.Unlock()

	innerCtx, cancel := context.WithCancel(ctx)
	inj.cancel = cancel

	open := func(queueNum uint16, isOutbound bool) (*nfqueue.Nfqueue, error) {
		cfg := &nfqueue.Config{
			NfQueue:      queueNum,
			MaxPacketLen: 65535,
			MaxQueueLen:  128,
			Copymode:     nfqueue.NfQnlCopyPacket,
			WriteTimeout: 15 * time.Millisecond,
		}
		nfq, err := nfqueue.Open(cfg)
		if err != nil {
			return nil, err
		}
		hook := func(a nfqueue.Attribute) int {
			if a.PacketID == nil || a.Payload == nil {
				if a.PacketID != nil {
					nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
				}
				return 0
			}
			inj.processPacket(nfq, *a.PacketID, *a.Payload, isOutbound)
			return 0
		}
		errFn := func(e error) int {
			select {
			case <-innerCtx.Done():
				return 1
			default:
				log.Debug("Geneva injector: nfqueue %d error: %v", queueNum, e)
				return 0
			}
		}
		if err := nfq.RegisterWithErrorFunc(innerCtx, hook, errFn); err != nil {
			nfq.Close()
			return nil, err
		}
		return nfq, nil
	}

	nfqOut, err := open(inj.outQueue, true)
	if err != nil {
		inj.release()
		return fmt.Errorf("geneva injector: register outbound queue: %w", err)
	}
	inj.nfqOut = nfqOut

	if inj.inEnabled {
		nfqIn, err := open(inj.inQueue, false)
		if err != nil {
			inj.release()
			return fmt.Errorf("geneva injector: register inbound queue: %w", err)
		}
		inj.nfqIn = nfqIn
		log.Info("Geneva injector: active on queues %d/%d (%d strategies, duplex)", inj.outQueue, inj.inQueue, len(inj.strategies))
		return nil
	}

	log.Info("Geneva injector: active on queue %d (%d strategies)", inj.outQueue, len(inj.strategies))
	return nil
}

func (inj *Injector) processPacket(nfq *nfqueue.Nfqueue, id uint32, packet []byte, isOutbound bool) {
	results := []Result{{Packet: packet}}
	for _, strat := range inj.strategies {
		var next []Result
		for _, res := range results {
			modified, err := strat.Apply(res.Packet, isOutbound)
			if err != nil {
				log.Debug("Geneva injector: strategy %q error: %v", strat.Trigger.Protocol, err)
				next = append(next, res)
				continue
			}
			if len(modified) == 0 {
				// Strategy dropped this packet - skip it
				continue
			}
			for i := range modified {
				if modified[i].Delay == 0 {
					modified[i].Delay = res.Delay
				}
			}
			next = append(next, modified...)
		}
		results = next
	}

	if len(results) == 0 {
		nfq.SetVerdict(id, nfqueue.NfDrop)
		return
	}

	// First result goes back through the queue (possibly modified) unless it
	// asked for a delay - a delayed packet has to be dropped here and re-injected
	// from a timer, because the verdict must be given now.
	if results[0].Delay > 0 {
		nfq.SetVerdict(id, nfqueue.NfDrop)
		inj.scheduleRaw(results[0])
	} else if err := nfq.SetVerdictModPacket(id, nfqueue.NfAccept, results[0].Packet); err != nil {
		log.Debug("Geneva injector: SetVerdictModPacket error: %v", err)
	}

	for _, extra := range results[1:] {
		inj.scheduleRaw(extra)
	}
}

// scheduleRaw puts a packet on the wire now, or after its delay.
func (inj *Injector) scheduleRaw(res Result) {
	packet := append([]byte(nil), res.Packet...)
	if res.Delay <= 0 {
		if err := inj.injectRaw(packet); err != nil {
			log.Debug("Geneva injector: inject extra packet failed: %v", err)
		}
		return
	}
	time.AfterFunc(res.Delay, func() {
		if err := inj.injectRaw(packet); err != nil {
			log.Debug("Geneva injector: delayed inject failed: %v", err)
		}
	})
}

func (inj *Injector) injectRaw(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short (%d bytes)", len(packet))
	}
	dstIP := net.IP(packet[16:20])
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP.To4())

	inj.mu.Lock()
	defer inj.mu.Unlock()
	if inj.closed || inj.rawFd < 0 {
		return fmt.Errorf("injector closed")
	}
	return syscall.Sendto(inj.rawFd, packet, 0, addr)
}

// Stop cancels the packet-processing goroutine and releases resources.
func (inj *Injector) Stop() {
	if inj.cancel != nil {
		inj.cancel()
		inj.cancel = nil
	}
	inj.release()
	log.Info("Geneva injector: stopped")
}

func (inj *Injector) release() {
	if inj.nfqOut != nil {
		inj.nfqOut.Close()
		inj.nfqOut = nil
	}
	if inj.nfqIn != nil {
		inj.nfqIn.Close()
		inj.nfqIn = nil
	}
	inj.mu.Lock()
	inj.closed = true
	if inj.rawFd >= 0 {
		syscall.Close(inj.rawFd)
		inj.rawFd = -1
	}
	inj.mu.Unlock()
}
