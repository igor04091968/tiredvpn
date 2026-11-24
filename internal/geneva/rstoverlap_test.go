package geneva

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestOverlapSplitReassembles(t *testing.T) {
	prim := NewOverlapSplitPrimitive(20, 2, 24)
	packet := packetWithPayload([]byte("GET /watch HTTP/1.1\r\nHost: pornhub.com\r\n\r\n"))

	res, err := prim.Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d segments, want 2", len(res))
	}

	first, second := payloadOf(t, res[0].Packet), payloadOf(t, res[1].Packet)
	if len(first) != 20 {
		t.Errorf("first segment = %d bytes, want 20", len(first))
	}
	if !bytes.HasSuffix(first, second[:2]) {
		t.Error("the segments do not overlap by two bytes")
	}

	// Reassembly: prefix, then the rest after the overlap.
	reassembled := append(append([]byte(nil), first...), second[2:]...)
	if !bytes.Equal(reassembled, payloadOf(t, packet)) {
		t.Errorf("reassembly = %q, want the original payload", reassembled)
	}

	wantSeq := binary.BigEndian.Uint32(packet[24:28]) + 18
	if got := binary.BigEndian.Uint32(res[1].Packet[24:28]); got != wantSeq {
		t.Errorf("second segment seq = %d, want %d", got, wantSeq)
	}
	if !validIPChecksum(res[0].Packet) || !validTCPChecksum(res[0].Packet) ||
		!validIPChecksum(res[1].Packet) || !validTCPChecksum(res[1].Packet) {
		t.Error("a segment carries a bad checksum")
	}
}

func TestOverlapSplitShortPayloadPasses(t *testing.T) {
	prim := NewOverlapSplitPrimitive(20, 2, 24)
	packet := packetWithPayload([]byte("GET / HTTP/1.1\r\n\r\n")) // 18 bytes

	res, err := prim.Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("a payload at or below MinLen was split")
	}
}

func TestBareRSTDrop(t *testing.T) {
	drop := &BareRSTDropPrimitive{}

	bare := createTestPacket()[:40]
	bare[33] = TCPFlagRST
	if res, _ := drop.Apply(bare); len(res) != 0 {
		t.Error("a payload-less RST was kept")
	}

	withData := packetWithPayload([]byte("x"))
	withData[33] = TCPFlagRST | TCPFlagACK
	if res, _ := drop.Apply(withData); len(res) != 1 {
		t.Error("a RST carrying data was dropped")
	}

	ack := createTestPacket()
	ack[33] = TCPFlagACK
	if res, _ := drop.Apply(ack); len(res) != 1 {
		t.Error("a non-RST was dropped")
	}
}

func TestMinimalRSTOverlapStrategy(t *testing.T) {
	strat := MinimalRSTOverlapStrategy()
	packet := httpRequestWithHost("pornhub.com")

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d segments, want 2", len(res))
	}

	// Non-HTTP outbound traffic is untouched.
	other := packetWithPayload([]byte("\x16\x03\x01\x00\x05hello"))
	if res, _ := strat.Apply(other, true); len(res) != 1 {
		t.Error("non-HTTP payload was split")
	}

	// Inbound: bare RST dropped, data-carrying RST kept.
	rst := createTestPacket()[:40]
	rst[33] = TCPFlagRST
	if res, _ := strat.Apply(rst, false); len(res) != 0 {
		t.Error("inbound bare RST was kept")
	}
}

func TestMinimalRSTOverlapRegistered(t *testing.T) {
	if GetStrategyByName("minimal_rst_overlap") == nil {
		t.Fatal("strategy is not registered")
	}
	found := false
	for _, s := range GetStrategiesByCountry("iran") {
		if s.GetName() == "Minimal RST filter + HTTP overlap" {
			found = true
		}
	}
	if !found {
		t.Error("strategy is not in the iran set")
	}
}
