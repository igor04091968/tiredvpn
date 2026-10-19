package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientWriterUsesConfiguredMTU(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, mtu := range []int{1280, 1400, 1500} {
			start, overhead := 20, 40
			if v6 {
				start, overhead = 40, 60
			}
			p := make([]byte, start+24)
			if v6 {
				p[0] = 0x60
				p[6] = 6
				binary.BigEndian.PutUint16(p[4:6], 24)
			} else {
				p[0] = 0x45
				p[9] = 6
				binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			}
			p[start+12], p[start+13], p[start+20], p[start+21] = 0x60, 2, 2, 4
			binary.BigEndian.PutUint16(p[start+22:start+24], 2000)
			a, b := net.Pipe()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			w := &ClientWriter{conn: a, mtu: mtu, done: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- w.SendPacket(p) }()
			frame := make([]byte, 4+len(p))
			if _, err := io.ReadFull(b, frame); err != nil {
				t.Fatal(err)
			}
			if got := int(binary.BigEndian.Uint16(frame[4+start+22 : 4+start+24])); got != mtu-overhead {
				t.Fatalf("v6=%v MTU=%d got MSS=%d", v6, mtu, got)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			a.Close()
			b.Close()
		}
	}
}

func TestClientWriterNegotiatedMTU(t *testing.T) {
	for _, pair := range [][3]int{{1500, 1280, 1280}, {1280, 1500, 1280}, {1500, 0, 1500}} {
		st := newTestSharedTUN(t)
		st.mtu = pair[0]
		a, b := net.Pipe()
		ip := net.IPv4(10, 8, 0, 2)
		w := st.RegisterClientGated(ip, "mtu-client", a, nil, nil, pair[1])
		if w.mtu != pair[2] {
			t.Errorf("server=%d client=%d writer=%d", pair[0], pair[1], w.mtu)
		}
		st.UnregisterClient(ip, w)
		a.Close()
		b.Close()
	}
}
