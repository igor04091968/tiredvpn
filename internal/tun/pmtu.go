package tun

import (
	"encoding/binary"
	"net"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// DefaultMTU is the default MTU for the TUN interface.
// 1280 is the IPv6 minimum link MTU and a conservative inner-link default.
// Outer transports must still handle their own segmentation and path MTU.
const DefaultMTU = 1280

// ClampTCPMSS lowers a TCP SYN/SYN-ACK MSS to fit the tunnel MTU for either
// IP family. Per RFC 6691 the advertised limit subtracts the fixed IP and TCP
// headers (40 bytes for IPv4, 60 for IPv6); senders account for their options.
// Fragmented, authenticated and malformed packets are left untouched.
func ClampTCPMSS(pkt []byte, mtu int) bool {
	tcpStart, end, overhead, ok := tcpPacketLayout(pkt)
	if !ok || mtu <= overhead || mtu-overhead > 65535 || end < tcpStart+20 {
		return false
	}
	flags := pkt[tcpStart+13]
	if flags&0x06 != 0x02 { // SYN set, RST clear
		return false
	}
	tcpHeaderLen := int(pkt[tcpStart+12]>>4) * 4
	if tcpHeaderLen < 20 || tcpStart+tcpHeaderLen > end {
		return false
	}
	maxMSS := uint16(mtu - overhead)
	for i, optEnd := tcpStart+20, tcpStart+tcpHeaderLen; i < optEnd; {
		kind := pkt[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= optEnd {
			break
		}
		optLen := int(pkt[i+1])
		if optLen < 2 || i+optLen > optEnd {
			break
		}
		if kind == 2 && optLen == 4 {
			currentMSS := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			if currentMSS <= maxMSS {
				return false
			}
			// RFC 1624 incremental update preserves the pseudo-header checksum
			// (including routing headers) without summing the whole packet.
			oldWord, newWord := currentMSS, maxMSS
			if (i+2-tcpStart)%2 != 0 { // TCP options need not be word aligned
				oldWord = oldWord<<8 | oldWord>>8
				newWord = newWord<<8 | newWord>>8
			}
			oldChecksum := binary.BigEndian.Uint16(pkt[tcpStart+16 : tcpStart+18])
			sum := uint32(^oldChecksum) + uint32(^oldWord) + uint32(newWord)
			for sum > 0xffff {
				sum = (sum & 0xffff) + (sum >> 16)
			}
			binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], ^uint16(sum))
			binary.BigEndian.PutUint16(pkt[i+2:i+4], maxMSS)
			log.Debug("TCP MSS clamped: %d -> %d", currentMSS, maxMSS)
			return true
		}
		i += optLen
	}
	return false
}

func tcpPacketLayout(pkt []byte) (start, end, overhead int, ok bool) {
	if len(pkt) < 20 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		start = int(pkt[0]&15) * 4
		end = int(binary.BigEndian.Uint16(pkt[2:4]))
		overhead = 40
		ok = start >= 20 && end >= start && end <= len(pkt) && pkt[9] == 6 && binary.BigEndian.Uint16(pkt[6:8])&0x3fff == 0
	case 6:
		var next byte
		next, start, end, ok = ipv6Payload(pkt, false)
		overhead = 60
		ok = ok && next == 6
	}
	return
}

// ipv6Payload walks a bounded extension chain. Real fragments and IPsec are
// not safe to rewrite; forError also accepts them for PMTU feedback. Atomic
// fragments are complete packets and are safe to clamp.
func ipv6Payload(pkt []byte, forError bool) (next byte, offset, end int, ok bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return
	}
	end = 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
	if end <= 40 || end > len(pkt) {
		return
	}
	next, offset = pkt[6], 40
	for n := 0; n < 16; n++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if offset+2 > end {
				return next, offset, end, false
			}
			size := (int(pkt[offset+1]) + 1) * 8
			if offset+size > end {
				return next, offset, end, false
			}
			next, offset = pkt[offset], offset+size
		case 44:
			if offset+8 > end {
				return next, offset, end, false
			}
			fragment := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			if fragment != 0 && !forError {
				return next, offset, end, false
			}
			// PTB applies to fragments too; a non-first fragment has no
			// upper-layer header to walk, so quote it as received.
			if fragment&0xfff8 != 0 {
				return next, offset, end, true
			}
			next, offset = pkt[offset], offset+8
		case 51:
			if !forError || offset+2 > end {
				return next, offset, end, false
			}
			size := (int(pkt[offset+1]) + 2) * 4
			if size < 12 || offset+size > end {
				return next, offset, end, false
			}
			next, offset = pkt[offset], offset+size
		case 50:
			// Ciphertext cannot be rewritten, but still needs outer PTB.
			return next, offset, end, forError
		default:
			return next, offset, end, true
		}
	}
	return next, offset, end, false
}

// recomputeTCPChecksum recalculates the TCP checksum for an IPv4 packet.
func recomputeTCPChecksum(pkt []byte, tcpStart int) {
	if len(pkt) < tcpStart+18 {
		return
	}

	// Clear existing checksum
	pkt[tcpStart+16] = 0
	pkt[tcpStart+17] = 0

	tcpLen := len(pkt) - tcpStart

	// Pseudo-header sum
	var sum uint32
	// Source IP
	sum += uint32(pkt[12])<<8 | uint32(pkt[13])
	sum += uint32(pkt[14])<<8 | uint32(pkt[15])
	// Dest IP
	sum += uint32(pkt[16])<<8 | uint32(pkt[17])
	sum += uint32(pkt[18])<<8 | uint32(pkt[19])
	// Protocol (TCP = 6)
	sum += 6
	// TCP length
	sum += uint32(tcpLen)

	// TCP segment
	for i := tcpStart; i < len(pkt)-1; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if (len(pkt)-tcpStart)%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}

	// Fold carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], checksum)
}

// BuildICMPFragNeeded builds an ICMP Type 3, Code 4 (Fragmentation Needed)
// packet in response to an oversized IP packet.
// nextHopMTU is the MTU to advertise in the ICMP message.
// srcIP is the IP that will be in the ICMP response's source (our TUN IP).
// origPkt is the original packet that was too large.
//
// Returns the complete IP+ICMP packet ready to write to the TUN device.
func BuildICMPFragNeeded(srcIP net.IP, origPkt []byte, nextHopMTU uint16) []byte {
	if len(origPkt) < 20 || origPkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(origPkt[0]&15) * 4
	total := int(binary.BigEndian.Uint16(origPkt[2:4]))
	if ihl < 20 || total < ihl || total > len(origPkt) || nextHopMTU < 68 || binary.BigEndian.Uint16(origPkt[6:8])&0x1fff != 0 {
		return nil
	}
	origPkt = origPkt[:total]
	source, dest := net.IP(origPkt[12:16]), net.IP(origPkt[16:20])
	if source.IsUnspecified() || source.IsMulticast() || source.Equal(net.IPv4bcast) || dest.IsMulticast() || dest.Equal(net.IPv4bcast) {
		return nil
	}
	if origPkt[9] == 1 && len(origPkt) > ihl {
		switch origPkt[ihl] {
		case 3, 4, 5, 11, 12:
			return nil
		}
	}

	// ICMP payload: original IP header + first 8 bytes of original payload
	origPayloadLen := len(origPkt)
	if origPayloadLen > 28 { // IP header (assumed 20) + 8 bytes
		ihl := int(origPkt[0]&0x0F) * 4
		maxCopy := ihl + 8
		if maxCopy > origPayloadLen {
			maxCopy = origPayloadLen
		}
		origPayloadLen = maxCopy
	}

	// Total: IP(20) + ICMP(8) + original fragment
	totalLen := 20 + 8 + origPayloadLen
	pkt := make([]byte, totalLen)

	// --- IPv4 Header ---
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	// TOS = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// ID, Flags, Fragment offset = 0
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMP

	// Source IP = our TUN IP
	src4 := srcIP.To4()
	if src4 == nil {
		return nil
	}
	copy(pkt[12:16], src4)

	// Dest IP = original packet's source IP
	copy(pkt[16:20], origPkt[12:16])

	// IP header checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	// --- ICMP Header ---
	icmpStart := 20
	pkt[icmpStart] = 3   // Type: Destination Unreachable
	pkt[icmpStart+1] = 4 // Code: Fragmentation Needed
	// Checksum at [icmpStart+2:icmpStart+4] - computed below
	// Unused (2 bytes) = 0
	// Next-Hop MTU (2 bytes)
	binary.BigEndian.PutUint16(pkt[icmpStart+6:icmpStart+8], nextHopMTU)

	// Copy original packet header + 8 bytes
	copy(pkt[icmpStart+8:], origPkt[:origPayloadLen])

	// ICMP checksum
	icmpLen := 8 + origPayloadLen
	var icmpSum uint32
	for i := icmpStart; i < icmpStart+icmpLen-1; i += 2 {
		icmpSum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if icmpLen%2 != 0 {
		icmpSum += uint32(pkt[icmpStart+icmpLen-1]) << 8
	}
	for icmpSum > 0xffff {
		icmpSum = (icmpSum & 0xffff) + (icmpSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[icmpStart+2:icmpStart+4], ^uint16(icmpSum))

	return pkt
}

// BuildICMPv6PacketTooBig creates a Type 2 error with the mandatory IPv6
// pseudo-header checksum. Its quote is capped so the entire error fits 1280.
func BuildICMPv6PacketTooBig(srcIP net.IP, origPkt []byte, mtu uint32) []byte {
	next, offset, end, ok := ipv6Payload(origPkt, true)
	src6 := srcIP.To16()
	if !ok || src6 == nil || srcIP.To4() != nil || srcIP.IsUnspecified() || srcIP.IsMulticast() || mtu < 1280 {
		return nil
	}
	origin := net.IP(origPkt[8:24])
	if origin.IsUnspecified() || origin.IsMulticast() {
		return nil
	}
	// RFC 4443: never answer an ICMPv6 error or redirect with another error.
	if next == 58 && (offset >= end || origPkt[offset] < 128 || origPkt[offset] == 137) {
		return nil
	}
	quoteLen := end
	if quoteLen > 1280-48 {
		quoteLen = 1280 - 48
	}
	pkt := make([]byte, 48+quoteLen)
	pkt[0], pkt[6], pkt[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	copy(pkt[8:24], src6)
	copy(pkt[24:40], origin)
	pkt[40] = 2
	binary.BigEndian.PutUint32(pkt[44:48], mtu)
	copy(pkt[48:], origPkt[:quoteLen])
	var sum uint32
	for i := 8; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	sum += uint32(len(pkt)-40) + 58
	for i := 40; i+1 < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if len(pkt)%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[42:44], ^uint16(sum))
	return pkt
}

// packetTooBigForPeer rejects an oversized packet received for this client.
// The local destination of the packet supplies the error's source address;
// the error must be framed back to the tunnel peer, never injected as inbound
// traffic into the local TUN (its destination is the remote sender).
func packetTooBigForPeer(pkt []byte, mtu int) []byte {
	if len(pkt) < 20 || mtu <= 0 || mtu > 65535 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		return BuildICMPFragNeeded(net.IP(pkt[16:20]), pkt, uint16(mtu))
	case 6:
		if len(pkt) >= 40 {
			return BuildICMPv6PacketTooBig(net.IP(pkt[24:40]), pkt, uint32(mtu))
		}
	}
	return nil
}
