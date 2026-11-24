package geneva

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHostHeaderSplitSplitsBeforeHost(t *testing.T) {
	strat := HostHeaderSplitStrategy()
	packet := httpRequestWithHost("pornhub.com")

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d segments, want 2", len(res))
	}

	first, second := payloadOf(t, res[0].Packet), payloadOf(t, res[1].Packet)
	if bytes.Contains(first, []byte("Host:")) {
		t.Errorf("first segment still carries the Host header: %q", first)
	}
	if !bytes.HasPrefix(second, []byte("Host: pornhub.com")) {
		t.Errorf("second segment does not start at the Host header: %q", second)
	}
	if !bytes.Equal(append(append([]byte(nil), first...), second...), payloadOf(t, packet)) {
		t.Error("the two segments do not reassemble into the original payload")
	}

	// The second segment must sit exactly after the first one.
	wantSeq := binary.BigEndian.Uint32(packet[24:28]) + uint32(len(first))
	if got := binary.BigEndian.Uint32(res[1].Packet[24:28]); got != wantSeq {
		t.Errorf("second segment seq = %d, want %d", got, wantSeq)
	}
	if !validIPChecksum(res[0].Packet) || !validTCPChecksum(res[0].Packet) ||
		!validIPChecksum(res[1].Packet) || !validTCPChecksum(res[1].Packet) {
		t.Error("a segment carries a bad checksum")
	}
}

func TestHostHeaderSplitLeavesOtherTraffic(t *testing.T) {
	strat := HostHeaderSplitStrategy()
	packet := packetWithPayload([]byte("GET / HTTP/1.1\r\n\r\n"))

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("a request without a Host header was split")
	}
}

func TestHostHeaderSplitInboundDropsRST(t *testing.T) {
	strat := HostHeaderSplitStrategy()
	rst := createTestPacket()
	rst[33] = TCPFlagRST

	res, err := strat.Apply(rst, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("inbound RST produced %d packets, want 0", len(res))
	}
}

func TestEarlySmallDropWindow(t *testing.T) {
	drop := NewEarlySmallDropPrimitive(120, 4)

	small := func() []byte {
		p := packetWithPayload(bytes.Repeat([]byte("x"), 40))
		p[33] = TCPFlagPSH | TCPFlagACK
		return p
	}

	for i := 1; i <= 4; i++ {
		res, err := drop.Apply(small())
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(res) != 0 {
			t.Errorf("packet %d inside the window was not dropped", i)
		}
	}

	res, err := drop.Apply(small())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 {
		t.Error("packet 5 outside the window was dropped")
	}
}

func TestEarlySmallDropKeepsLargeAndEmpty(t *testing.T) {
	drop := NewEarlySmallDropPrimitive(120, 4)

	large := packetWithPayload(bytes.Repeat([]byte("x"), 400))
	large[33] = TCPFlagPSH | TCPFlagACK
	if res, _ := drop.Apply(large); len(res) != 1 {
		t.Error("a large early segment was dropped")
	}

	pureAck := createTestPacket()
	pureAck[33] = TCPFlagACK
	if res, _ := drop.Apply(pureAck); len(res) != 1 {
		t.Error("a payload-less ACK was dropped")
	}
}

func TestHostHeaderSplitRegistered(t *testing.T) {
	if GetStrategyByName("host_header_split") == nil {
		t.Fatal("strategy is not registered")
	}
	found := false
	for _, s := range GetStrategiesByCountry("china") {
		if s.GetName() == "Host-header split" {
			found = true
		}
	}
	if !found {
		t.Error("strategy is not in the china set")
	}
}
