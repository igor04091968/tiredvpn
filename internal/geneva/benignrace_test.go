package geneva

import (
	"bytes"
	"testing"
	"time"
)

func TestBenignHostRaceOrderAndDelay(t *testing.T) {
	strat := BenignHostRaceStrategy("pornhub.com", "example.com")
	packet := httpRequestWithHost("pornhub.com")
	before := append([]byte(nil), packet...)

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d packets, want 2 (benign twin, real)", len(res))
	}
	if !bytes.Equal(packet, before) {
		t.Error("Apply modified the caller's buffer")
	}

	benign, real := res[0], res[1]

	if benign.Delay != 0 {
		t.Errorf("benign twin delay = %v, want 0", benign.Delay)
	}
	if real.Delay != 8*time.Millisecond {
		t.Errorf("real packet delay = %v, want 8ms", real.Delay)
	}

	if !bytes.Contains(payloadOf(t, benign.Packet), []byte("Host: example.com")) {
		t.Errorf("first packet payload = %q, want the allowed host", payloadOf(t, benign.Packet))
	}
	if bytes.Contains(payloadOf(t, benign.Packet), []byte("pornhub.com")) {
		t.Error("the benign twin still carries the forbidden host")
	}
	if len(benign.Packet) != len(packet) {
		t.Error("the benign twin is not length-preserving")
	}

	// Both copies must be fully valid: the server may accept either.
	if !validIPChecksum(benign.Packet) || !validTCPChecksum(benign.Packet) {
		t.Error("the benign twin carries a bad checksum")
	}
	if !bytes.Equal(real.Packet, before) {
		t.Error("the second packet is not the untouched original")
	}
}

func TestBenignHostRaceDropsInboundRST(t *testing.T) {
	strat := BenignHostRaceStrategy("", "")
	rst := createTestPacket()
	rst[33] = TCPFlagRST

	res, err := strat.Apply(rst, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("inbound RST produced %d packets, want 0", len(res))
	}

	ack := createTestPacket()
	ack[33] = TCPFlagACK
	if res, _ := strat.Apply(ack, false); len(res) != 1 {
		t.Error("inbound ACK was dropped")
	}
}

func TestBenignHostRaceIgnoresOtherHosts(t *testing.T) {
	strat := BenignHostRaceStrategy("", "")
	packet := httpRequestWithHost("wikipedia.org")

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("a request without the forbidden host was manipulated")
	}
}

func TestBenignHostRaceRegistered(t *testing.T) {
	if GetStrategyByName("benign_host_race") == nil {
		t.Fatal("strategy is not registered")
	}
	found := false
	for _, s := range GetStrategiesByCountry("china") {
		if s.GetName() == "Benign-Host race" {
			found = true
		}
	}
	if !found {
		t.Error("strategy is not in the china set")
	}
}
