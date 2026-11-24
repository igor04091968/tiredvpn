package geneva

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func httpRequestWithHost(host string) []byte {
	return packetWithPayload([]byte("GET /watch HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: test\r\n\r\n"))
}

func TestGhostDecoyRealTriple(t *testing.T) {
	strat := GhostDecoyRealStrategy("pornhub.com", "example.com")
	packet := httpRequestWithHost("pornhub.com")
	before := append([]byte(nil), packet...)

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("got %d packets, want 3 (ghost, decoy, real)", len(res))
	}
	if !bytes.Equal(packet, before) {
		t.Error("Apply modified the caller's buffer")
	}

	ghost, decoy, real := res[0].Packet, res[1].Packet, res[2].Packet

	// Ghost: one payload byte, same seq, bad checksum.
	if got := len(payloadOf(t, ghost)); got != 1 {
		t.Errorf("ghost payload = %d bytes, want 1", got)
	}
	if binary.BigEndian.Uint32(ghost[24:28]) != binary.BigEndian.Uint32(packet[24:28]) {
		t.Error("ghost does not sit at the real sequence number")
	}
	if validIPChecksum(ghost) && validTCPChecksum(ghost) {
		t.Error("ghost carries valid checksums; endpoints would accept it")
	}

	// Decoy: allowed host, same length as the real packet, bad checksum.
	decoyPayload := payloadOf(t, decoy)
	if !bytes.Contains(decoyPayload, []byte("Host: example.com")) {
		t.Errorf("decoy payload = %q, want the allowed host", decoyPayload)
	}
	if bytes.Contains(decoyPayload, []byte("pornhub.com")) {
		t.Error("decoy still carries the forbidden host")
	}
	if len(decoy) != len(packet) {
		t.Errorf("decoy is %d bytes, real is %d - the replacement was not length-preserving", len(decoy), len(packet))
	}
	if validIPChecksum(decoy) && validTCPChecksum(decoy) {
		t.Error("decoy carries valid checksums; the server would accept it too")
	}

	// Real: untouched.
	if !bytes.Equal(real, before) {
		t.Error("the third packet is not the untouched original")
	}
}

func TestGhostDecoyRealPadsShortAllowedHost(t *testing.T) {
	strat := GhostDecoyRealStrategy("averylongforbiddenhost.example", "ok.example")
	packet := httpRequestWithHost("averylongforbiddenhost.example")

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	decoy := res[1].Packet
	if len(decoy) != len(packet) {
		t.Fatalf("decoy length %d, want %d", len(decoy), len(packet))
	}
	wantPrefix := "Host: ok.example" + strings.Repeat("x", len("averylongforbiddenhost.example")-len("ok.example"))
	if !bytes.Contains(payloadOf(t, decoy), []byte(wantPrefix)) {
		t.Errorf("decoy payload = %q, want %q", payloadOf(t, decoy), wantPrefix)
	}
}

func TestGhostDecoyRealIgnoresOtherHosts(t *testing.T) {
	strat := GhostDecoyRealStrategy("", "")
	packet := httpRequestWithHost("wikipedia.org")

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("a request without the forbidden host was manipulated")
	}
}

func TestGhostDecoyRealDropsInboundRST(t *testing.T) {
	strat := GhostDecoyRealStrategy("", "")

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
	res, err = strat.Apply(ack, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("inbound ACK produced %d packets, want 1", len(res))
	}
}

func TestGhostDecoyRealRegistered(t *testing.T) {
	if GetStrategyByName("ghost_decoy_real") == nil {
		t.Fatal("strategy is not registered")
	}
	found := false
	for _, s := range GetStrategiesByCountry("china") {
		if s.GetName() == "Ghost + Host decoy + real" {
			found = true
		}
	}
	if !found {
		t.Error("strategy is not in the china set")
	}
	if s := GetStrategyByName("ghost_decoy_real"); s.String() == "" {
		t.Error("empty strategy string")
	}
}
