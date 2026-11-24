package geneva

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// validIPChecksum reports whether the IP header checksum is correct.
func validIPChecksum(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	ipHeaderLen := int((p[0] & 0x0F) * 4)
	if ipHeaderLen > len(p) {
		return false
	}
	var sum uint32
	for i := 0; i < ipHeaderLen; i += 2 {
		if i == 10 {
			continue // checksum field counts as zero
		}
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum) == binary.BigEndian.Uint16(p[10:12])
}

// validTCPChecksum reports whether the TCP checksum is correct.
func validTCPChecksum(p []byte) bool {
	ipHeaderLen := int((p[0] & 0x0F) * 4)
	tcpLen := len(p) - ipHeaderLen
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	sum += 6
	sum += uint32(tcpLen)
	for i := ipHeaderLen; i+1 < len(p); i += 2 {
		if i == ipHeaderLen+16 {
			continue // checksum field counts as zero
		}
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	if len(p)%2 != 0 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum) == binary.BigEndian.Uint16(p[ipHeaderLen+16:ipHeaderLen+18])
}

func payloadOf(t *testing.T, p []byte) []byte {
	t.Helper()
	start, _, err := payloadBounds(p)
	if err != nil {
		t.Fatalf("payloadBounds: %v", err)
	}
	return p[start:]
}

func TestTamperNoRecalcInvalidatesChecksum(t *testing.T) {
	packet := createTestPacket()
	recalculateTCPChecksum(packet)
	if !validTCPChecksum(packet) {
		t.Fatal("fixture checksum is not valid to begin with")
	}

	res, err := NewTamperPrimitiveNoRecalc("flags", uint8(TCPFlagRST)).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d packets, want 1", len(res))
	}
	out := res[0].Packet
	if out[33] != TCPFlagRST {
		t.Errorf("flags = %#x, want RST", out[33])
	}
	if validTCPChecksum(out) {
		t.Error("checksum is still valid; a checksum-blind endpoint would accept the decoy")
	}
	if !validIPChecksum(out) {
		t.Error("IP checksum was disturbed for a TCP-field tamper")
	}
}

func TestTamperNoRecalcTTLCorruptsIPChecksum(t *testing.T) {
	packet := createTestPacket()
	res, err := NewTamperPrimitiveNoRecalc("ttl", uint8(3)).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := res[0].Packet
	if out[8] != 3 {
		t.Errorf("ttl = %d, want 3", out[8])
	}
	if validIPChecksum(out) {
		t.Error("IP checksum still valid after a no-recalc TTL tamper")
	}
}

func TestCorruptChecksumPrimitive(t *testing.T) {
	packet := createTestPacket()
	recalculateTCPChecksum(packet)

	res, err := (&CorruptChecksumPrimitive{}).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := res[0].Packet
	if validIPChecksum(out) || validTCPChecksum(out) {
		t.Error("at least one checksum survived corruption")
	}
	if !bytes.Equal(out[:10], packet[:10]) {
		t.Error("corruption touched header bytes other than the checksums")
	}
}

func TestLoadTamperReplacesAndFixesLengths(t *testing.T) {
	packet := createTestPacket()
	before := append([]byte(nil), packet...)

	prim := NewLoadTamperPrimitive([]byte("Geneva"), []byte("VeryLongHostName"))
	res, err := prim.Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := res[0].Packet

	if !bytes.Equal(packet, before) {
		t.Error("Apply modified the caller's buffer")
	}
	if !bytes.Contains(payloadOf(t, out), []byte("VeryLongHostName")) {
		t.Errorf("payload = %q, want the replacement", payloadOf(t, out))
	}
	if got, want := binary.BigEndian.Uint16(out[2:4]), len(out); int(got) != want {
		t.Errorf("IP total length = %d, want %d", got, want)
	}
	if !validIPChecksum(out) || !validTCPChecksum(out) {
		t.Error("checksums not repaired after a payload rewrite")
	}
}

func TestLoadTamperLimitAndPassthrough(t *testing.T) {
	packet := packetWithPayload([]byte("aXaXaX"))

	res, err := NewLoadTamperPrimitive([]byte("a"), []byte("bb")).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := string(payloadOf(t, res[0].Packet)); got != "bbXaXaX" {
		t.Errorf("payload = %q, want only the first occurrence replaced", got)
	}

	res, err = NewLoadTamperPrimitiveAll([]byte("a"), []byte("bb")).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := string(payloadOf(t, res[0].Packet)); got != "bbXbbXbbX" {
		t.Errorf("payload = %q, want every occurrence replaced", got)
	}

	res, err = NewLoadTamperPrimitive([]byte("absent"), []byte("x")).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(res[0].Packet, packet) {
		t.Error("missing pattern did not pass the packet through unchanged")
	}
}

func TestFragmentAtSplitsInsideMarker(t *testing.T) {
	packet := packetWithPayload([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	res, err := NewFragmentAtPrimitive([]byte("example.com"), 4).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d fragments, want 2", len(res))
	}
	if got := string(payloadOf(t, res[0].Packet)); got != "GET / HTTP/1.1\r\nHost: exam" {
		t.Errorf("first fragment payload = %q", got)
	}
	if got := string(payloadOf(t, res[1].Packet)); got != "ple.com\r\n\r\n" {
		t.Errorf("second fragment payload = %q", got)
	}
	seq1 := binary.BigEndian.Uint32(res[1].Packet[24:28])
	if seq1 != 1000+uint32(len(payloadOf(t, res[0].Packet))) {
		t.Errorf("second fragment seq = %d, want %d", seq1, 1000+len(payloadOf(t, res[0].Packet)))
	}
	for i, r := range res {
		if !validIPChecksum(r.Packet) || !validTCPChecksum(r.Packet) {
			t.Errorf("fragment %d has a bad checksum", i)
		}
	}
}

func TestFragmentAtWithoutMarkerIsPassthrough(t *testing.T) {
	packet := createTestPacket()
	res, err := NewFragmentAtPrimitive([]byte("nope"), 0).Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("missing marker did not pass the packet through")
	}
}

func TestDelaySurvivesChaining(t *testing.T) {
	packet := createTestPacket()
	tree := NewActionTree(NewDelayPrimitive(7*time.Millisecond), NewTamperPrimitive("ttl", uint8(5)))

	res, err := tree.Execute(packet)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d packets, want 1", len(res))
	}
	if res[0].Delay != 7*time.Millisecond {
		t.Errorf("delay = %v, want 7ms - a later primitive erased it", res[0].Delay)
	}
	if res[0].Packet[8] != 5 {
		t.Error("the primitive after the delay did not run")
	}
}

func TestTTLTriggerOperators(t *testing.T) {
	packet := createTestPacket() // TTL 64
	cases := []struct {
		op    string
		value uint8
		want  bool
	}{
		{"==", 64, true},
		{"==", 63, false},
		{"!=", 63, true},
		{"<", 65, true},
		{"<", 64, false},
		{">", 63, true},
		{"<=", 64, true},
		{">=", 65, false},
	}
	for _, c := range cases {
		s := NewStrategy(Trigger{Protocol: "TCP", Field: "ttl", Operator: c.op, Value: c.value}, nil, nil)
		got, err := s.Match(packet)
		if err != nil {
			t.Fatalf("%s %d: %v", c.op, c.value, err)
		}
		if got != c.want {
			t.Errorf("ttl %s %d = %v, want %v", c.op, c.value, got, c.want)
		}
	}
}

// buildClientHello builds a minimal TLS 1.2 ClientHello with one SNI extension.
func buildClientHello(host string) []byte {
	ext := make([]byte, 0, 5+len(host))
	ext = append(ext, 0x00, 0x00) // server_name
	body := make([]byte, 0, 3+len(host))
	body = append(body, 0x00, byte(len(host)+3), 0x00) // list len, host_name
	body = append(body, byte(len(host)>>8), byte(len(host)))
	body = append(body, host...)
	ext = append(ext, byte(len(body)>>8), byte(len(body)))
	ext = append(ext, body...)

	hs := make([]byte, 0, 64+len(ext))
	hs = append(hs, 0x01, 0, 0, 0) // handshake type + length placeholder
	hs = append(hs, 0x03, 0x03)    // client version
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0)                      // session id len
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hs = append(hs, 0x01, 0x00)             // compression
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)))
	hs = append(hs, ext...)
	putUint24(hs[1:4], len(hs)-4)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func packetWithPayload(payload []byte) []byte {
	p := make([]byte, 40+len(payload))
	copy(p, createTestPacket()[:40])
	copy(p[40:], payload)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	recalculateIPChecksum(p)
	recalculateTCPChecksum(p)
	return p
}

func TestSNIRewrite(t *testing.T) {
	packet := packetWithPayload(buildClientHello("example.com"))
	before := append([]byte(nil), packet...)

	res, err := NewSNIRewritePrimitive("").Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := res[0].Packet

	if !bytes.Equal(packet, before) {
		t.Error("Apply modified the caller's buffer")
	}
	want := "xn--6578616d706c652e636f6d"
	if !bytes.Contains(payloadOf(t, out), []byte(want)) {
		t.Fatalf("payload does not contain %q", want)
	}
	if bytes.Contains(payloadOf(t, out), []byte("example.com")) {
		t.Error("original hostname still present")
	}
	if !validIPChecksum(out) || !validTCPChecksum(out) {
		t.Error("checksums not repaired")
	}

	// The record, handshake, extensions and SNI lengths must all have grown by
	// the same delta, and the extension must still parse.
	delta := len(want) - len("example.com")
	payload := payloadOf(t, out)
	if got := int(binary.BigEndian.Uint16(payload[3:5])); got != len(payload)-5 {
		t.Errorf("record length = %d, want %d", got, len(payload)-5)
	}
	if got := readUint24(payload[6:9]); got != len(payload)-9 {
		t.Errorf("handshake length = %d, want %d", got, len(payload)-9)
	}
	span, ok := locateSNI(payload)
	if !ok {
		t.Fatal("rewritten ClientHello no longer parses")
	}
	if got := string(payload[span.nameStart:span.nameEnd]); got != want {
		t.Errorf("SNI = %q, want %q", got, want)
	}
	if got := int(binary.BigEndian.Uint16(payload[span.listLenField:])); got != 3+len(want) {
		t.Errorf("server_name_list length = %d, want %d", got, 3+len(want))
	}
	if got := int(binary.BigEndian.Uint16(payload[span.extLenField:])); got != 5+len(want) {
		t.Errorf("extension length = %d, want %d", got, 5+len(want))
	}
	_ = delta
}

func TestSNIRewriteNonTLSIsPassthrough(t *testing.T) {
	packet := createTestPacket() // payload "Hello Geneva!!"
	res, err := NewSNIRewritePrimitive("").Apply(packet)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || !bytes.Equal(res[0].Packet, packet) {
		t.Error("non-TLS packet was modified")
	}
}
