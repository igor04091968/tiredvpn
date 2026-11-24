package geneva

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Result is one packet produced by a primitive.
//
// Delay is the time to wait before putting the packet on the wire. Zero means
// "send now". A delay is what turns a decoy from "sent just before the real
// packet" into "sent just before the real packet by a measurable margin", which
// is the whole point of the benign-first race: the censor must see the decoy
// first, and on a loopback-fast path two back-to-back writes can arrive in
// either order.
type Result struct {
	Packet []byte
	Delay  time.Duration
}

// Primitive represents a Geneva packet manipulation primitive
type Primitive interface {
	// Apply executes the primitive on a TCP packet
	Apply(packet []byte) ([]Result, error)
	// String returns a human-readable description
	String() string
}

// DropPrimitive drops a packet (returns empty list)
type DropPrimitive struct{}

// Apply drops the packet
func (d *DropPrimitive) Apply(packet []byte) ([]Result, error) {
	return nil, nil // Empty list = packet dropped
}

// String returns description
func (d *DropPrimitive) String() string {
	return "drop"
}

// TamperPrimitive modifies TCP/IP header fields
type TamperPrimitive struct {
	Field string // "flags", "seq", "ack", "win", "chksum", "ttl"
	Value any    // New value or modification
	// NoRecalc leaves the transport (or IP, for ttl) checksum stale instead of
	// recomputing it. The endpoints then drop the packet while a middlebox that
	// does not verify checksums still parses it - the ghost/decoy trick.
	NoRecalc bool
}

// NewTamperPrimitive creates a tamper primitive with a valid checksum
func NewTamperPrimitive(field string, value any) *TamperPrimitive {
	return &TamperPrimitive{
		Field: field,
		Value: value,
	}
}

// NewTamperPrimitiveNoRecalc creates a tamper primitive whose checksum is left
// deliberately invalid, so only middleboxes that skip checksum validation see
// the modified packet.
func NewTamperPrimitiveNoRecalc(field string, value any) *TamperPrimitive {
	return &TamperPrimitive{
		Field:    field,
		Value:    value,
		NoRecalc: true,
	}
}

// Apply modifies TCP header field
func (t *TamperPrimitive) Apply(packet []byte) ([]Result, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}

	// Parse IP header
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}

	// Create modified copy
	modified := make([]byte, len(packet))
	copy(modified, packet)

	tcpStart := ipHeaderLen
	ipField := false

	switch t.Field {
	case "flags":
		// TCP flags are at offset 13 in TCP header
		if val, ok := t.Value.(uint8); ok {
			modified[tcpStart+13] = val
		} else {
			return nil, errors.New("invalid value for flags")
		}
	case "seq":
		// TCP sequence number at offset 4
		if val, ok := t.Value.(uint32); ok {
			binary.BigEndian.PutUint32(modified[tcpStart+4:], val)
		} else {
			return nil, errors.New("invalid value for seq")
		}
	case "ack":
		// TCP acknowledgment number at offset 8
		if val, ok := t.Value.(uint32); ok {
			binary.BigEndian.PutUint32(modified[tcpStart+8:], val)
		} else {
			return nil, errors.New("invalid value for ack")
		}
	case "win":
		// TCP window size at offset 14
		if val, ok := t.Value.(uint16); ok {
			binary.BigEndian.PutUint16(modified[tcpStart+14:], val)
		} else {
			return nil, errors.New("invalid value for win")
		}
	case "chksum":
		// Explicit checksum override — caller knows what they're doing (desync)
		if val, ok := t.Value.(uint16); ok {
			binary.BigEndian.PutUint16(modified[tcpStart+16:], val)
		} else {
			return nil, errors.New("invalid value for chksum")
		}
	case "ttl":
		// IP TTL at offset 8
		if val, ok := t.Value.(uint8); ok {
			modified[8] = val
			ipField = true
		} else {
			return nil, errors.New("invalid value for ttl")
		}
	default:
		return nil, errors.New("unknown tamper field: " + t.Field)
	}

	if t.NoRecalc {
		if ipField {
			corruptIPChecksum(modified)
		} else {
			corruptTCPChecksum(modified)
		}
	} else if ipField {
		recalculateIPChecksum(modified)
	} else {
		recalculateTCPChecksum(modified)
	}

	return []Result{{Packet: modified}}, nil
}

// String returns description
func (t *TamperPrimitive) String() string {
	if t.NoRecalc {
		return "tamper{" + t.Field + ",corrupt}"
	}
	return "tamper{" + t.Field + "}"
}

// CorruptChecksumPrimitive invalidates both the IP and TCP checksums without
// touching any other field. Chain it after a LoadTamperPrimitive to build a
// decoy that endpoints discard but a checksum-blind middlebox parses.
type CorruptChecksumPrimitive struct{}

// Apply corrupts the IP and TCP checksums
func (c *CorruptChecksumPrimitive) Apply(packet []byte) ([]Result, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}

	modified := make([]byte, len(packet))
	copy(modified, packet)
	corruptIPChecksum(modified)
	corruptTCPChecksum(modified)
	return []Result{{Packet: modified}}, nil
}

// String returns description
func (c *CorruptChecksumPrimitive) String() string {
	return "corrupt-chksum"
}

// LoadTamperPrimitive rewrites TCP payload bytes.
//
// It is the primitive the Host-header decoys need: the decoy must carry a
// benign Host while the real packet keeps the forbidden one. Old is matched
// literally in the payload, so a strategy can target "Host: pornhub.com" and
// leave the rest of the request alone.
type LoadTamperPrimitive struct {
	Old []byte
	New []byte
	// Limit caps the number of replacements; zero means every occurrence.
	Limit int
}

// NewLoadTamperPrimitive replaces the first occurrence of old with new.
func NewLoadTamperPrimitive(old, new []byte) *LoadTamperPrimitive {
	return &LoadTamperPrimitive{Old: old, New: new, Limit: 1}
}

// NewLoadTamperPrimitiveAll replaces every occurrence of old with new.
func NewLoadTamperPrimitiveAll(old, new []byte) *LoadTamperPrimitive {
	return &LoadTamperPrimitive{Old: old, New: new}
}

// Apply rewrites the payload and fixes the IP length and checksums. When old is
// absent the packet is returned unchanged, so a strategy degrades to a plain
// duplicate instead of failing.
func (l *LoadTamperPrimitive) Apply(packet []byte) ([]Result, error) {
	if len(l.Old) == 0 {
		return nil, errors.New("empty load-tamper pattern")
	}
	if len(packet) < 20 {
		return nil, errors.New("packet too short for IP header")
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return nil, errors.New("packet too short for TCP header")
	}
	tcpStart := ipHeaderLen
	tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
	payloadStart := tcpStart + tcpHeaderLen
	if len(packet) <= payloadStart {
		return []Result{{Packet: packet}}, nil
	}

	payload := packet[payloadStart:]
	limit := l.Limit
	if limit <= 0 {
		limit = bytes.Count(payload, l.Old)
	}

	rewritten := make([]byte, 0, len(payload)+limit*len(l.New))
	rest := payload
	for replaced := 0; replaced < limit; replaced++ {
		idx := bytes.Index(rest, l.Old)
		if idx < 0 {
			break
		}
		rewritten = append(rewritten, rest[:idx]...)
		rewritten = append(rewritten, l.New...)
		rest = rest[idx+len(l.Old):]
	}
	if len(rewritten) == 0 {
		return []Result{{Packet: packet}}, nil
	}
	rewritten = append(rewritten, rest...)

	modified := make([]byte, payloadStart+len(rewritten))
	copy(modified, packet[:payloadStart])
	copy(modified[payloadStart:], rewritten)

	binary.BigEndian.PutUint16(modified[2:4], uint16(len(modified)))
	recalculateIPChecksum(modified)
	recalculateTCPChecksum(modified)

	return []Result{{Packet: modified}}, nil
}

// String returns description
func (l *LoadTamperPrimitive) String() string {
	return "load{" + string(l.Old) + "→" + string(l.New) + "}"
}

// FragmentPrimitive splits TCP payload into smaller segments
type FragmentPrimitive struct {
	Offset int // Byte offset to fragment at
	Size   int // Fragment size (if Offset is 0, use Size for equal chunks)
}

// NewFragmentPrimitive creates a fragment primitive
func NewFragmentPrimitive(offset, size int) *FragmentPrimitive {
	return &FragmentPrimitive{
		Offset: offset,
		Size:   size,
	}
}

// Apply fragments the packet
func (f *FragmentPrimitive) Apply(packet []byte) ([]Result, error) {
	payloadStart, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if payloadLen == 0 {
		return []Result{{Packet: packet}}, nil
	}

	// Determine fragment offset
	fragmentOffset := f.Offset
	if fragmentOffset == 0 && f.Size > 0 {
		fragmentOffset = f.Size
	}

	return splitPayload(packet, payloadStart, fragmentOffset)
}

// String returns description
func (f *FragmentPrimitive) String() string {
	if f.Offset > 0 {
		return "fragment{offset=" + strconv.Itoa(f.Offset) + "}"
	}
	return "fragment{size=" + strconv.Itoa(f.Size) + "}"
}

// FragmentAtPrimitive splits the payload at a position found in the payload
// itself instead of at a fixed offset.
//
// A fixed offset cannot follow the field a censor actually inspects: the Host
// header sits after a variable-length request line, and the hostname sits after
// a variable-length "Host: ". Marker locates the field, Delta picks the byte
// inside it. Delta 0 splits immediately before the marker, len(Marker) right
// after it, and a value in between splits inside the marker - which is how the
// hostname is cut across two segments.
type FragmentAtPrimitive struct {
	Marker []byte
	Delta  int
}

// NewFragmentAtPrimitive splits Delta bytes after the first occurrence of marker.
func NewFragmentAtPrimitive(marker []byte, delta int) *FragmentAtPrimitive {
	return &FragmentAtPrimitive{Marker: marker, Delta: delta}
}

// Apply splits the payload at the marker. Without a marker match the packet is
// returned unchanged.
func (f *FragmentAtPrimitive) Apply(packet []byte) ([]Result, error) {
	payloadStart, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if payloadLen == 0 || len(f.Marker) == 0 {
		return []Result{{Packet: packet}}, nil
	}

	payload := packet[payloadStart:]
	idx := bytes.Index(payload, f.Marker)
	if idx < 0 {
		return []Result{{Packet: packet}}, nil
	}

	return splitPayload(packet, payloadStart, idx+f.Delta)
}

// String returns description
func (f *FragmentAtPrimitive) String() string {
	return "fragment-at{" + string(f.Marker) + "," + strconv.Itoa(f.Delta) + "}"
}

// TruncatePrimitive keeps only the first N payload bytes.
//
// It is the "ghost" half of a ghost/decoy/real triple: a one-byte segment at
// the real sequence number, with a bad checksum, is enough to make a DPI that
// parses the first bytes of a flow commit to a one-byte request body before the
// real request arrives.
type TruncatePrimitive struct {
	N int
}

// NewTruncatePrimitive keeps the first n payload bytes.
func NewTruncatePrimitive(n int) *TruncatePrimitive {
	return &TruncatePrimitive{N: n}
}

// Apply truncates the payload. A payload already at or below N is returned
// unchanged.
func (t *TruncatePrimitive) Apply(packet []byte) ([]Result, error) {
	payloadStart, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if t.N <= 0 || payloadLen <= t.N {
		return []Result{{Packet: packet}}, nil
	}

	modified := make([]byte, payloadStart+t.N)
	copy(modified, packet[:payloadStart+t.N])
	binary.BigEndian.PutUint16(modified[2:4], uint16(len(modified)))
	recalculateIPChecksum(modified)
	recalculateTCPChecksum(modified)

	return []Result{{Packet: modified}}, nil
}

// String returns description
func (t *TruncatePrimitive) String() string {
	return "truncate{" + strconv.Itoa(t.N) + "}"
}

// RSTDropPrimitive drops segments with the RST flag set and passes everything
// else through. It is an inbound primitive: a censor's forged RST arrives from
// the server's address and is indistinguishable from a real one except by
// timing, so the only safe move is to swallow them all and let the connection
// die of its own timeout when the reset was genuine.
type RSTDropPrimitive struct{}

// Apply drops RST segments.
func (r *RSTDropPrimitive) Apply(packet []byte) ([]Result, error) {
	flags, err := ParseTCPFlags(packet)
	if err != nil {
		return nil, err
	}
	if flags&TCPFlagRST != 0 {
		return nil, nil
	}
	return []Result{{Packet: packet}}, nil
}

// String returns description
func (r *RSTDropPrimitive) String() string { return "drop-rst" }

// EarlySmallDropPrimitive drops small PSH+ACK segments near the start of a
// flow. Injected block pages are tiny (a 302 or a one-line 404), arrive within
// the first few server segments and carry no data the client needs, so they can
// be thrown away before they poison the TLS handshake.
//
// The window is per flow and the primitive is stateful, unlike the rest of this
// file: "early" cannot be decided from a single packet. State is a plain
// counter that is deleted once the window closes, so the map only ever holds
// flows that are inside their first Window inbound packets. It is bounded by
// maxTrackedFlows, after which the oldest decision is simply forgotten.
//
// Only the injector may use it: the userspace path has no inbound direction.
type EarlySmallDropPrimitive struct {
	MaxLen int
	Window int

	mu   sync.Mutex
	seen map[flowKey]int
}

const maxTrackedFlows = 4096

type flowKey struct {
	src, dst     [4]byte
	sport, dport uint16
}

// NewEarlySmallDropPrimitive drops inbound PSH+ACK segments shorter than maxLen
// during the first window packets of a flow.
func NewEarlySmallDropPrimitive(maxLen, window int) *EarlySmallDropPrimitive {
	return &EarlySmallDropPrimitive{MaxLen: maxLen, Window: window, seen: make(map[flowKey]int)}
}

// Apply counts the packet against its flow and drops it when it is a small
// early PSH+ACK.
func (e *EarlySmallDropPrimitive) Apply(packet []byte) ([]Result, error) {
	_, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	flags, err := ParseTCPFlags(packet)
	if err != nil {
		return nil, err
	}

	key := flowKeyOf(packet)

	e.mu.Lock()
	if e.seen == nil {
		e.seen = make(map[flowKey]int)
	}
	count := e.seen[key] + 1
	if count > e.Window {
		delete(e.seen, key)
	} else {
		if len(e.seen) >= maxTrackedFlows {
			clear(e.seen)
		}
		e.seen[key] = count
	}
	e.mu.Unlock()

	if count > e.Window {
		return []Result{{Packet: packet}}, nil
	}
	if payloadLen > 0 && payloadLen < e.MaxLen && flags&TCPFlagPSH != 0 && flags&TCPFlagACK != 0 {
		return nil, nil
	}
	return []Result{{Packet: packet}}, nil
}

// String returns description
func (e *EarlySmallDropPrimitive) String() string {
	return "drop-early-small{" + strconv.Itoa(e.MaxLen) + "," + strconv.Itoa(e.Window) + "}"
}

func flowKeyOf(packet []byte) flowKey {
	var k flowKey
	copy(k.src[:], packet[12:16])
	copy(k.dst[:], packet[16:20])
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	k.sport = binary.BigEndian.Uint16(packet[ipHeaderLen : ipHeaderLen+2])
	k.dport = binary.BigEndian.Uint16(packet[ipHeaderLen+2 : ipHeaderLen+4])
	return k
}

// BareRSTDropPrimitive drops RST segments that carry no payload and passes
// everything else through. A real reset from the server is bare; a censor's
// forged one usually is too, but so is a real one, so this is the narrowest
// useful filter - a RST that carries data is never dropped.
type BareRSTDropPrimitive struct{}

// Apply drops payload-less RST segments.
func (b *BareRSTDropPrimitive) Apply(packet []byte) ([]Result, error) {
	flags, err := ParseTCPFlags(packet)
	if err != nil {
		return nil, err
	}
	if flags&TCPFlagRST == 0 {
		return []Result{{Packet: packet}}, nil
	}
	_, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if payloadLen == 0 {
		return nil, nil
	}
	return []Result{{Packet: packet}}, nil
}

// String returns description
func (b *BareRSTDropPrimitive) String() string { return "drop-bare-rst" }

// OverlapSplitPrimitive splits the payload in two in-order segments that
// overlap by Overlap bytes. Both segments are valid and the server needs no
// support: it reassembles them into the original payload, seeing the overlapped
// bytes twice. A DPI that resolves overlaps naively can be pushed into
// mis-parsing the bytes around the split, which is where the Host header sits.
//
// This is not the seqovl primitive: seqovl prepends a fake segment below the
// server's rcv_nxt and tags it so the server can recognise it. Here both
// segments carry real data at real sequence numbers.
type OverlapSplitPrimitive struct {
	// PrefixLen is the first segment's payload length. Clamped to half the
	// payload.
	PrefixLen int
	// Overlap is how many trailing bytes of the first segment are repeated at
	// the start of the second. Clamped to half the prefix.
	Overlap int
	// MinLen is the shortest payload that is worth splitting.
	MinLen int
}

// NewOverlapSplitPrimitive splits a payload of at least minLen bytes into two
// segments overlapping by overlap bytes, the first at most prefixLen long.
func NewOverlapSplitPrimitive(prefixLen, overlap, minLen int) *OverlapSplitPrimitive {
	return &OverlapSplitPrimitive{PrefixLen: prefixLen, Overlap: overlap, MinLen: minLen}
}

// Apply splits the payload. Payloads at or below MinLen pass through.
func (o *OverlapSplitPrimitive) Apply(packet []byte) ([]Result, error) {
	payloadStart, payloadLen, err := payloadBounds(packet)
	if err != nil {
		return nil, err
	}
	if payloadLen <= o.MinLen || payloadLen < 4 {
		return []Result{{Packet: packet}}, nil
	}

	prefix := o.PrefixLen
	if prefix <= 0 || prefix > payloadLen/2 {
		prefix = payloadLen / 2
	}
	overlap := o.Overlap
	if overlap < 1 {
		overlap = 1
	}
	if overlap > prefix/2 {
		overlap = prefix / 2
	}
	if prefix-overlap <= 0 || prefix >= payloadLen {
		return []Result{{Packet: packet}}, nil
	}

	return splitPayloadOverlap(packet, payloadStart, prefix, overlap)
}

// String returns description
func (o *OverlapSplitPrimitive) String() string {
	return "overlap-split{" + strconv.Itoa(o.PrefixLen) + "," + strconv.Itoa(o.Overlap) + "}"
}

func splitPayloadOverlap(packet []byte, payloadStart, prefix, overlap int) ([]Result, error) {
	payload := packet[payloadStart:]
	header := packet[:payloadStart]
	tcpStart := payloadStart - int((packet[payloadStart-20+12]>>4)*4)
	seq := binary.BigEndian.Uint32(packet[tcpStart+4:])

	first := make([]byte, len(header)+prefix)
	copy(first, header)
	copy(first[payloadStart:], payload[:prefix])
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	recalculateIPChecksum(first)
	recalculateTCPChecksum(first)

	second := make([]byte, len(header)+len(payload)-(prefix-overlap))
	copy(second, header)
	copy(second[payloadStart:], payload[prefix-overlap:])
	binary.BigEndian.PutUint32(second[tcpStart+4:], seq+uint32(prefix-overlap))
	binary.BigEndian.PutUint16(second[2:4], uint16(len(second)))
	recalculateIPChecksum(second)
	recalculateTCPChecksum(second)

	return []Result{{Packet: first}, {Packet: second}}, nil
}

// splitPayload cuts a packet into two in-order segments at payload offset.
// Offsets outside the payload return the packet unchanged.
func splitPayload(packet []byte, payloadStart, fragmentOffset int) ([]Result, error) {
	payload := packet[payloadStart:]
	if fragmentOffset <= 0 || fragmentOffset >= len(payload) {
		return []Result{{Packet: packet}}, nil
	}

	header := packet[:payloadStart]
	tcpStart := payloadStart - int((packet[payloadStart-20+12]>>4)*4)

	// First fragment: header + payload[:offset]
	frag1 := make([]byte, len(header)+fragmentOffset)
	copy(frag1, header)
	copy(frag1[payloadStart:], payload[:fragmentOffset])

	// Update IP total length and recompute both IP and TCP checksums.
	binary.BigEndian.PutUint16(frag1[2:4], uint16(len(frag1)))
	recalculateIPChecksum(frag1)
	recalculateTCPChecksum(frag1)

	// Second fragment: header + payload[offset:]
	frag2 := make([]byte, len(header)+len(payload)-fragmentOffset)
	copy(frag2, header)
	copy(frag2[payloadStart:], payload[fragmentOffset:])

	// Update sequence number for second fragment
	seqNum := binary.BigEndian.Uint32(frag2[tcpStart+4:])
	seqNum += uint32(fragmentOffset)
	binary.BigEndian.PutUint32(frag2[tcpStart+4:], seqNum)

	// Update IP total length and recompute both checksums.
	binary.BigEndian.PutUint16(frag2[2:4], uint16(len(frag2)))
	recalculateIPChecksum(frag2)
	recalculateTCPChecksum(frag2)

	return []Result{{Packet: frag1}, {Packet: frag2}}, nil
}

// payloadBounds validates a packet and returns the payload start and length.
func payloadBounds(packet []byte) (start, length int, err error) {
	if len(packet) < 20 {
		return 0, 0, errors.New("packet too short for IP header")
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return 0, 0, errors.New("packet too short for TCP header")
	}
	tcpHeaderLen := int((packet[ipHeaderLen+12] >> 4) * 4)
	start = ipHeaderLen + tcpHeaderLen
	if start > len(packet) {
		return 0, 0, errors.New("invalid TCP header length")
	}
	return start, len(packet) - start, nil
}

// DuplicatePrimitive sends a duplicate packet
type DuplicatePrimitive struct {
	Count int // Number of duplicates (default 1)
}

// NewDuplicatePrimitive creates a duplicate primitive
func NewDuplicatePrimitive(count int) *DuplicatePrimitive {
	if count < 1 {
		count = 1
	}
	return &DuplicatePrimitive{
		Count: count,
	}
}

// Apply duplicates the packet
func (d *DuplicatePrimitive) Apply(packet []byte) ([]Result, error) {
	result := make([]Result, d.Count+1)

	// Original packet
	result[0] = Result{Packet: packet}

	// Duplicates
	for i := 0; i < d.Count; i++ {
		dup := make([]byte, len(packet))
		copy(dup, packet)
		result[i+1] = Result{Packet: dup}
	}

	return result, nil
}

// String returns description
func (d *DuplicatePrimitive) String() string {
	if d.Count == 1 {
		return "duplicate"
	}
	return "duplicate{count=" + strconv.Itoa(d.Count) + "}"
}

// SendPrimitive sends a packet as-is (no-op)
type SendPrimitive struct{}

// Apply returns the packet unmodified
func (s *SendPrimitive) Apply(packet []byte) ([]Result, error) {
	return []Result{{Packet: packet}}, nil
}

// String returns description
func (s *SendPrimitive) String() string {
	return "send"
}

// DelayPrimitive stamps a send delay on every packet that passes through it.
// Place it at the end of the branch whose packets should go out later.
type DelayPrimitive struct {
	Delay time.Duration
}

// NewDelayPrimitive creates a delay primitive
func NewDelayPrimitive(d time.Duration) *DelayPrimitive {
	return &DelayPrimitive{Delay: d}
}

// Apply sets the delay on the packet
func (d *DelayPrimitive) Apply(packet []byte) ([]Result, error) {
	return []Result{{Packet: packet, Delay: d.Delay}}, nil
}

// String returns description
func (d *DelayPrimitive) String() string {
	return "delay{" + d.Delay.String() + "}"
}

// recalculateIPChecksum recalculates IP header checksum
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Zero out existing checksum
	packet[10] = 0
	packet[11] = 0

	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if ipHeaderLen > len(packet) {
		return
	}

	// Calculate checksum
	var sum uint32
	for i := 0; i < ipHeaderLen; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// Add carry
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	checksum := uint16(^sum)

	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)
}

// corruptIPChecksum flips the IP checksum so it can never be valid.
func corruptIPChecksum(packet []byte) {
	if len(packet) < 12 {
		return
	}
	checksum := binary.BigEndian.Uint16(packet[10:12])
	binary.BigEndian.PutUint16(packet[10:12], ^checksum)
}

// recalculateTCPChecksum recalculates the TCP checksum over the IPv4 pseudo-header.
// Must be called after any TCP header field modification (flags, seq, ack, win).
func recalculateTCPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if ipHeaderLen+20 > len(packet) {
		return
	}
	tcpStart := ipHeaderLen
	tcpLen := len(packet) - tcpStart

	// Zero out TCP checksum field
	packet[tcpStart+16] = 0
	packet[tcpStart+17] = 0

	// Pseudo-header: src IP(4) + dst IP(4) + zero(1) + proto(1) + tcp length(2)
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	sum += uint32(6) // TCP protocol number
	sum += uint32(tcpLen)

	// TCP header + data
	for i := tcpStart; i+1 < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if len(packet)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	checksum := uint16(^sum)
	packet[tcpStart+16] = byte(checksum >> 8)
	packet[tcpStart+17] = byte(checksum)
}

// corruptTCPChecksum flips the TCP checksum so it can never be valid.
func corruptTCPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if ipHeaderLen+18 > len(packet) {
		return
	}
	checksum := binary.BigEndian.Uint16(packet[ipHeaderLen+16 : ipHeaderLen+18])
	binary.BigEndian.PutUint16(packet[ipHeaderLen+16:ipHeaderLen+18], ^checksum)
}

// TCPFlags represents TCP header flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
	TCPFlagECE = 0x40
	TCPFlagCWR = 0x80
)

// ParseTCPFlags parses TCP flags from packet
func ParseTCPFlags(packet []byte) (uint8, error) {
	if len(packet) < 20 {
		return 0, errors.New("packet too short for IP header")
	}

	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+20 {
		return 0, errors.New("packet too short for TCP header")
	}

	return packet[ipHeaderLen+13], nil
}
