package geneva

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSNIPunycodeDecoy(t *testing.T) {
	strat := SNIPunycodeDecoyStrategy()
	packet := packetWithPayload(buildClientHello("example.com"))
	before := append([]byte(nil), packet...)

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d packets, want 2 (decoy, real)", len(res))
	}
	if !bytes.Equal(packet, before) {
		t.Error("Apply modified the caller's buffer")
	}

	decoy, real := res[0].Packet, res[1].Packet

	want := "xn--" + hex.EncodeToString([]byte("example.com"))
	if !bytes.Contains(payloadOf(t, decoy), []byte(want)) {
		t.Errorf("decoy payload does not carry %q", want)
	}
	if bytes.Contains(payloadOf(t, decoy), []byte("example.com")) {
		t.Error("decoy still carries the plain hostname")
	}
	if validIPChecksum(decoy) && validTCPChecksum(decoy) {
		t.Error("decoy carries valid checksums; the server would accept it")
	}
	if !bytes.Equal(real, before) {
		t.Error("the second packet is not the untouched original")
	}
}

func TestSNIPunycodeDecoyIgnoresNonTLS(t *testing.T) {
	strat := SNIPunycodeDecoyStrategy()
	packet := packetWithPayload([]byte("GET / HTTP/1.1\r\n\r\n"))

	res, err := strat.Apply(packet, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("a non-TLS payload was manipulated")
	}
}

func TestSNIPunycodeDecoyRegistered(t *testing.T) {
	if GetStrategyByName("sni_punycode_decoy") == nil {
		t.Fatal("strategy is not registered")
	}
	for _, country := range []string{"iran", "turkey"} {
		found := false
		for _, s := range GetStrategiesByCountry(country) {
			if s.GetName() == "SNI punycode decoy" {
				found = true
			}
		}
		if !found {
			t.Errorf("strategy is not in the %s set", country)
		}
	}
}
