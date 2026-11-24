package geneva

import (
	"encoding/binary"
	"encoding/hex"
)

// SNIRewritePrimitive rewrites the SNI in a TLS ClientHello to an
// indistinguishable-looking label while keeping the rest of the handshake
// byte-identical.
//
// The rewritten name is Prefix + hex(original), so "example.com" becomes
// "xn--6578616d706c652e636f6d": still a syntactically valid LDH label, still
// ASCII, but not a name any SNI blocklist contains. A censor that matches the
// hostname exactly sees nothing to block, and the server only needs to be told
// the mapping (the tunnel does not depend on the name resolving).
//
// Only a ClientHello that lies entirely inside one TCP segment is handled; a
// split or coalesced handshake is returned unchanged rather than half-rewritten.
type SNIRewritePrimitive struct {
	// Prefix is prepended to the hex form of the original name. Defaults to
	// "xn--" so the result looks like an IDN A-label.
	Prefix string
}

// NewSNIRewritePrimitive creates an SNI rewriter with the given prefix.
func NewSNIRewritePrimitive(prefix string) *SNIRewritePrimitive {
	if prefix == "" {
		prefix = "xn--"
	}
	return &SNIRewritePrimitive{Prefix: prefix}
}

// sniSpan locates the SNI name inside the payload.
type sniSpan struct {
	nameStart, nameEnd int // offsets into the payload
	lenField           int // offset of the 2-byte server_name length
	listLenField       int // offset of the 2-byte server_name_list length
	extLenField        int // offset of the 2-byte server_name extension length
	extsLenField       int // offset of the 2-byte extensions length
	hsLenField         int // offset of the 3-byte handshake length
	recLenField        int // offset of the 2-byte TLS record length
}

// Apply rewrites the SNI. Any parse failure or an oversized result leaves the
// packet unchanged.
func (s *SNIRewritePrimitive) Apply(packet []byte) ([]Result, error) {
	payloadStart, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if payloadLen == 0 {
		return []Result{{Packet: packet}}, nil
	}

	span, ok := locateSNI(packet[payloadStart:])
	if !ok {
		return []Result{{Packet: packet}}, nil
	}

	payload := packet[payloadStart:]
	old := payload[span.nameStart:span.nameEnd]
	newName := s.Prefix + hex.EncodeToString(old)
	if len(newName) > 0xFFFF || len(newName) == len(old) {
		return []Result{{Packet: packet}}, nil
	}
	if int(binary.BigEndian.Uint16(payload[span.extLenField:]))+len(newName)-len(old) > 0xFFFF {
		return []Result{{Packet: packet}}, nil
	}

	// Rebuild the payload with the new name in place.
	rewritten := make([]byte, 0, len(payload)-len(old)+len(newName))
	rewritten = append(rewritten, payload[:span.nameStart]...)
	rewritten = append(rewritten, newName...)
	rewritten = append(rewritten, payload[span.nameEnd:]...)

	// Fix the length fields from the innermost out. Every field after the name
	// grew by the same delta.
	delta := len(newName) - len(old)
	binary.BigEndian.PutUint16(rewritten[span.lenField:], uint16(len(newName)))
	binary.BigEndian.PutUint16(rewritten[span.listLenField:], uint16(int(binary.BigEndian.Uint16(rewritten[span.listLenField:]))+delta))
	binary.BigEndian.PutUint16(rewritten[span.extLenField:], uint16(int(binary.BigEndian.Uint16(rewritten[span.extLenField:]))+delta))
	binary.BigEndian.PutUint16(rewritten[span.extsLenField:], uint16(int(binary.BigEndian.Uint16(rewritten[span.extsLenField:]))+delta))
	putUint24(rewritten[span.hsLenField:], readUint24(rewritten[span.hsLenField:])+delta)
	binary.BigEndian.PutUint16(rewritten[span.recLenField:], uint16(int(binary.BigEndian.Uint16(rewritten[span.recLenField:]))+delta))

	modified := make([]byte, payloadStart+len(rewritten))
	copy(modified, packet[:payloadStart])
	copy(modified[payloadStart:], rewritten)

	binary.BigEndian.PutUint16(modified[2:4], uint16(len(modified)))
	recalculateIPChecksum(modified)
	recalculateTCPChecksum(modified)

	return []Result{{Packet: modified}}, nil
}

// String returns description
func (s *SNIRewritePrimitive) String() string {
	return "sni{" + s.Prefix + "hex}"
}

// locateSNI walks a TLS ClientHello payload and returns the SNI span. It is
// deliberately strict: anything unexpected means "not ours to touch".
func locateSNI(p []byte) (sniSpan, bool) {
	var span sniSpan

	// TLS record header: type(1) version(2) length(2)
	if len(p) < 5 || p[0] != 0x16 || p[1] != 0x03 {
		return span, false
	}
	recLen := int(binary.BigEndian.Uint16(p[3:5]))
	if 5+recLen > len(p) {
		return span, false
	}
	span.recLenField = 3

	// Handshake header: type(1) length(3)
	hs := p[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return span, false
	}
	hsLen := readUint24(hs[1:4])
	if 4+hsLen > len(hs) {
		return span, false
	}
	span.hsLenField = 6

	// client_version(2) random(32)
	i := 4 + 2 + 32
	if i > len(hs) {
		return span, false
	}

	// session_id
	if i+1 > len(hs) {
		return span, false
	}
	sessLen := int(hs[i])
	i += 1 + sessLen
	if i > len(hs) {
		return span, false
	}

	// cipher_suites
	if i+2 > len(hs) {
		return span, false
	}
	csLen := int(binary.BigEndian.Uint16(hs[i:]))
	i += 2 + csLen
	if i > len(hs) {
		return span, false
	}

	// compression_methods
	if i+1 > len(hs) {
		return span, false
	}
	compLen := int(hs[i])
	i += 1 + compLen
	if i > len(hs) {
		return span, false
	}

	// extensions
	if i+2 > len(hs) {
		return span, false
	}
	extsLen := int(binary.BigEndian.Uint16(hs[i:]))
	span.extsLenField = 5 + i
	i += 2
	extsEnd := i + extsLen
	if extsEnd > len(hs) {
		return span, false
	}

	for i+4 <= extsEnd {
		extType := binary.BigEndian.Uint16(hs[i:])
		extLen := int(binary.BigEndian.Uint16(hs[i+2:]))
		body := i + 4
		if body+extLen > extsEnd {
			return span, false
		}
		if extType == 0x0000 {
			// server_name_list: length(2), then entries: type(1) length(2) name
			if extLen < 5 || body+2 > extsEnd {
				return span, false
			}
			listLen := int(binary.BigEndian.Uint16(hs[body:]))
			if body+2+listLen > extsEnd || listLen < 3 {
				return span, false
			}
			if hs[body+2] != 0x00 {
				return span, false // not a host_name entry
			}
			nameLen := int(binary.BigEndian.Uint16(hs[body+3:]))
			nameStart := body + 5
			if nameStart+nameLen > extsEnd || nameLen == 0 {
				return span, false
			}
			span.lenField = 5 + body + 3
			span.listLenField = 5 + body
			span.extLenField = 5 + i + 2
			span.nameStart = 5 + nameStart
			span.nameEnd = span.nameStart + nameLen
			return span, true
		}
		i = body + extLen
	}

	return span, false
}

func readUint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func putUint24(b []byte, v int) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
