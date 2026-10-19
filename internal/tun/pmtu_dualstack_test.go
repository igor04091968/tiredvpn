package tun

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func foldedSum(data []byte, initial uint32) uint16 {
	sum := initial
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func testTransportSum(pkt []byte, start int, proto byte) uint16 {
	var end int
	var sum uint32
	if pkt[0]>>4 == 6 {
		end = 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		sum = uint32(foldedSum(pkt[8:40], 0))
	} else {
		end = int(binary.BigEndian.Uint16(pkt[2:4]))
		sum = uint32(foldedSum(pkt[12:20], 0))
	}
	sum += uint32(end-start) + uint32(proto)
	return foldedSum(pkt[start:end], sum)
}

func testSYN6(mss uint16, ext, odd bool) ([]byte, int, int) {
	start := 40
	if ext {
		start += 8
	}
	tcpLen := 24
	if odd {
		tcpLen = 28
	}
	p := make([]byte, start+tcpLen+3) // odd payload length exercises checksum tails
	p[0], p[6], p[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	copy(p[8:24], net.ParseIP("2001:db8::1").To16())
	copy(p[24:40], net.ParseIP("fd00::2").To16())
	if ext {
		p[6] = 60
		p[40] = 6
	}
	p[start+12], p[start+13] = byte(tcpLen/4)<<4, 2
	option := start + 20
	if odd {
		p[option] = 1
		option++
	}
	p[option], p[option+1] = 2, 4
	binary.BigEndian.PutUint16(p[option+2:option+4], mss)
	binary.BigEndian.PutUint16(p[start+16:start+18], ^testTransportSum(p, start, 6))
	return p, start, option + 2
}

func TestClampTCPMSSIPv6(t *testing.T) {
	for _, ext := range []bool{false, true} {
		for _, odd := range []bool{false, true} {
			p, start, mss := testSYN6(1440, ext, odd)
			if !ClampTCPMSS(p, 1280) {
				t.Fatal("IPv6 SYN was not clamped")
			}
			if got := binary.BigEndian.Uint16(p[mss : mss+2]); got != 1220 {
				t.Fatalf("MSS=%d", got)
			}
			if got := testTransportSum(p, start, 6); got != 0xffff {
				t.Fatalf("bad IPv6 TCP checksum: %x", got)
			}
			old := append([]byte(nil), p...)
			if ClampTCPMSS(p, 1500) || !bytes.Equal(old, p) {
				t.Fatal("smaller MSS was raised")
			}
		}
	}
}

func TestClampTCPMSSIPv4OddOptionAndPadding(t *testing.T) {
	p := buildTCPSYNWithMSS(1460)
	p = append(p, 0, 0, 0, 0)
	copy(p[41:45], p[40:44])
	p[40] = 1
	p[32] = 0x70
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	recomputeTCPChecksum(p, 20)
	p = append(p, 99, 99, 99) // link padding must not enter the TCP checksum
	if !ClampTCPMSS(p, 1280) {
		t.Fatal("not clamped")
	}
	if got := testTransportSum(p, 20, 6); got != 0xffff {
		t.Fatalf("bad IPv4 checksum: %x", got)
	}
}

func TestClampTCPMSSSkipsFragmentsAndMalformed(t *testing.T) {
	p, start, _ := testSYN6(1440, true, false)
	for _, kind := range []byte{44, 50, 51} {
		q := append([]byte(nil), p...)
		q[6] = kind
		if kind == 44 {
			q[40] = 6
			binary.BigEndian.PutUint16(q[42:44], 1)
		}
		old := append([]byte(nil), q...)
		if ClampTCPMSS(q, 1280) || !bytes.Equal(old, q) {
			t.Fatalf("rewrote fragment/IPsec %d", kind)
		}
	}
	// Complete atomic fragment is safe to rewrite.
	p[6] = 44
	if !ClampTCPMSS(p, 1280) || testTransportSum(p, start, 6) != 0xffff {
		t.Fatal("atomic fragment clamp failed")
	}
	q := buildTCPSYNWithMSS(1460)
	q[6] = 0x20
	if ClampTCPMSS(q, 1280) {
		t.Fatal("rewrote IPv4 first fragment")
	}
	p, _, _ = testSYN6(1440, false, false)
	for n := 0; n < len(p); n++ {
		if ClampTCPMSS(p[:n], 1280) {
			t.Fatalf("rewrote truncated packet %d", n)
		}
	}
	for _, mtu := range []int{-1, 0, 20, 60, 100000} {
		if ClampTCPMSS(p, mtu) {
			t.Fatalf("accepted MTU %d", mtu)
		}
	}
}

func testLarge6(size int, next byte) []byte {
	p := make([]byte, size)
	p[0], p[6], p[7] = 0x60, next, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(size-40))
	copy(p[8:24], net.ParseIP("2001:db8::1").To16())
	copy(p[24:40], net.ParseIP("fd00::2").To16())
	return p
}

func TestICMPv6PacketTooBig(t *testing.T) {
	for _, size := range []int{81, 1500, 9000} {
		p := testLarge6(size, 17)
		response := packetTooBigForPeer(p, 1280)
		if response == nil || len(response) > 1280 || response[0]>>4 != 6 || response[40] != 2 || response[41] != 0 {
			t.Fatalf("invalid PTB, size=%d", size)
		}
		if !net.IP(response[8:24]).Equal(net.IP(p[24:40])) || !net.IP(response[24:40]).Equal(net.IP(p[8:24])) {
			t.Fatal("reversed PTB direction")
		}
		if binary.BigEndian.Uint32(response[44:48]) != 1280 {
			t.Fatal("wrong advertised MTU")
		}
		if testTransportSum(response, 40, 58) != 0xffff {
			t.Fatal("invalid ICMPv6 checksum")
		}
		if !bytes.Equal(response[48:], p[:len(response)-48]) {
			t.Fatal("quote corrupted")
		}
		if BuildICMPFragNeeded(net.IPv4(10, 8, 0, 1), p, 1280) != nil {
			t.Fatal("IPv6 produced IPv4 error")
		}
	}
	p := testLarge6(1500, 58)
	p[40] = 2
	if packetTooBigForPeer(p, 1280) != nil {
		t.Fatal("answered ICMPv6 error")
	}
	p[6] = 60
	p[40] = 58
	p[41] = 0
	p[48] = 1
	if packetTooBigForPeer(p, 1280) != nil {
		t.Fatal("answered ICMPv6 error behind extension")
	}
	p = testLarge6(1500, 17)
	copy(p[8:24], net.IPv6zero)
	if packetTooBigForPeer(p, 1280) != nil {
		t.Fatal("answered unspecified sender")
	}
}

func TestOversizedFeedbackReturnsOverTunnel(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p := testLarge6(1500, 17)
		if !ipv6 {
			p = make([]byte, 1500)
			copy(p, buildTCPSYNWithMSS(1460))
			binary.BigEndian.PutUint16(p[2:4], 1500)
		}
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(2 * time.Second))
		b.SetDeadline(time.Now().Add(2 * time.Second))
		done := make(chan error, 1)
		go func() {
			if _, err := b.Write(p); err != nil {
				done <- err
				return
			}
			var head [4]byte
			if _, err := io.ReadFull(b, head[:]); err != nil {
				done <- err
				return
			}
			reply := make([]byte, binary.BigEndian.Uint32(head[:]))
			if _, err := io.ReadFull(b, reply); err != nil {
				done <- err
				return
			}
			if !bytes.Equal(reply, packetTooBigForPeer(p, 1280)) {
				done <- io.ErrUnexpectedEOF
				return
			}
			_, err := b.Write([]byte{1, 2, 3, 4})
			done <- err
		}()
		// No file attached: this also proves PMTU feedback is not injected into TUN.
		dev := &TUNDevice{mtu: 1500, atomicMTU: 1280}
		if got := handleOversizedPacket(dev, &frameWriteConn{Conn: a}, uint32(len(p))); got != "dropped" {
			t.Fatalf("%s", got)
		}
		marker := make([]byte, 4)
		if _, err := io.ReadFull(a, marker); err != nil || !bytes.Equal(marker, []byte{1, 2, 3, 4}) {
			t.Fatal("lost next frame")
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		a.Close()
		b.Close()
	}
	if got := handleOversizedPacket(&TUNDevice{mtu: 1280}, nil, 65536); got != "server_frame_too_large" {
		t.Fatalf("unbounded frame: %s", got)
	}
}

type shortFrameConn struct {
	net.Conn
	data bytes.Buffer
}

func (c *shortFrameConn) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return c.data.Write(p)
}
func TestFrameWritesStayContiguous(t *testing.T) {
	raw := &shortFrameConn{}
	conn := &frameWriteConn{Conn: raw}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(b byte) { defer wg.Done(); _, _ = conn.Write(bytes.Repeat([]byte{b}, 64)) }(byte(i))
	}
	wg.Wait()
	if raw.data.Len() != 20*64 {
		t.Fatal("short writes lost data")
	}
	p := raw.data.Bytes()
	for i := 0; i < len(p); i += 64 {
		if !bytes.Equal(p[i:i+64], bytes.Repeat(p[i:i+1], 64)) {
			t.Fatal("interleaved frames")
		}
	}
}

func TestPMTUFeedbackBudget(t *testing.T) {
	c := &frameWriteConn{}
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !c.allowPMTU(now) {
			t.Fatal("initial burst rejected")
		}
	}
	if c.allowPMTU(now) {
		t.Fatal("unlimited ICMP errors")
	}
	if !c.allowPMTU(now.Add(101 * time.Millisecond)) {
		t.Fatal("budget did not refill")
	}
	if !(&frameWriteConn{}).allowPMTU(now) {
		t.Fatal("one tunnel exhausted another")
	}
}

func TestVPNClientReturnsPMTUToRemoteSender(t *testing.T) {
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	b.SetDeadline(time.Now().Add(2 * time.Second))
	v := &VPNClient{conn: &frameWriteConn{Conn: a}, tun: &TUNDevice{mtu: 1280}, running: 1}
	done := make(chan struct{})
	go func() { defer close(done); v.readFromServer() }()
	defer func() { atomic.StoreInt32(&v.running, 0); a.Close(); b.Close(); <-done }()
	p := testLarge6(1500, 17)
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame, uint32(len(p)))
	copy(frame[4:], p)
	if _, err := b.Write(frame); err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(b, head[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(b, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, packetTooBigForPeer(p, 1280)) {
		t.Fatal("PMTU not returned to peer")
	}
}

func TestICMPv6FragmentTooBig(t *testing.T) {
	for _, fragment := range []uint16{1, 8, 9} {
		p := testLarge6(1500, 44)
		p[40] = 17
		binary.BigEndian.PutUint16(p[42:44], fragment)
		r := packetTooBigForPeer(p, 1280)
		if r == nil || testTransportSum(r, 40, 58) != 0xffff {
			t.Fatalf("fragment %d lost PMTU feedback", fragment)
		}
	}
}
