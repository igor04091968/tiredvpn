package geneva

import "time"

// Pre-discovered Geneva strategies for various censorship systems
// Based on academic research and real-world testing

// decoyThenReal builds the tree every packet-level strategy here needs: one
// duplicate, the decoy manipulated, the real packet sent untouched.
//
// The chained form these strategies used before - NewActionTree(dup, tamper) -
// cannot express that. ActionNode.Execute applies each following primitive to
// every result of the one before, so the tamper hit the original as well as the
// copy: Russia TSPU 1 put TTL=8 on the real SYN, which then expired before
// reaching the server; TSPU 3 turned the real PSH-ACK into an RST; China GFW 2
// and Turkey 1 tampered first and duplicated afterwards, so the untouched
// packet was never sent at all. Branch routing is what keeps the two apart, see
// ActionTree.Execute.
//
// The decoy goes out first. The point of all of these is to put a packet in
// front of the middlebox before the real one arrives - a low-TTL SYN it
// processes and the server never sees, an RST that poisons its flow table, a
// SYN-ACK that desynchronises its state machine. Behind the real packet a decoy
// has nothing left to poison.
//
// Branch 0 receives the original and branch 1 the copy, but at this point the
// two are byte-identical, so tampering "the original" and tampering the copy
// are the same operation. What matters is that exactly one of the two is
// manipulated. TamperPrimitive.Apply writes into a fresh buffer, so the packet
// handed to Apply is never modified in place.
func decoyThenReal(decoy Primitive) *ActionTree {
	tree := NewActionTree(NewDuplicatePrimitive(1))
	tree.AddBranch(NewActionTree(decoy))            // result 0: the decoy
	tree.AddBranch(NewActionTree(&SendPrimitive{})) // result 1: the real packet
	return tree
}

// ChinaGFWStrategy1 - Effective against China's GFW
// Strategy: "[TCP:flags:S]-duplicate(tamper{TTL:10})-|"
// Description: Duplicate SYN packets with low TTL to exhaust middlebox state
func ChinaGFWStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 1",
			"description": "Duplicate SYN with low TTL",
		},
	}

	// Outbound: a low-TTL decoy SYN, then the real SYN untouched
	tamperTTL := NewTamperPrimitive("ttl", uint8(10))

	return NewStrategy(trigger, decoyThenReal(tamperTTL), nil)
}

// ChinaGFWStrategy2 - Alternative GFW bypass
// Strategy: "[TCP:flags:S]-tamper{flags:SA}-duplicate-|"
// Description: Send fake SYN-ACK before real SYN to confuse DPI
func ChinaGFWStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 2",
			"description": "Fake SYN-ACK confusion",
		},
	}

	// Outbound: a fake SYN-ACK decoy, then the real SYN untouched
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagSYN|TCPFlagACK))

	return NewStrategy(trigger, decoyThenReal(tamperFlags), nil)
}

// ChinaGFWStrategy3 - Fragment-based evasion
// Strategy: "[TCP:flags:PA]-fragment{offset:2}-|"
// Description: Fragment PSH-ACK packets to evade keyword detection
func ChinaGFWStrategy3() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 3",
			"description": "Fragment PSH-ACK packets",
		},
	}

	// Outbound: fragment payload at offset 2
	frag := NewFragmentPrimitive(2, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// IranDPIStrategy1 - Effective against Iranian DPI
// Strategy: "[TCP:flags:S]-tamper{seq:10000}-duplicate-|"
// Description: Tamper sequence number on duplicate to desync DPI
func IranDPIStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Iran DPI Strategy 1",
			"description": "Sequence number tampering",
		},
	}

	// Outbound: a decoy with a desynchronising seq, then the real SYN untouched
	tamperSeq := NewTamperPrimitive("seq", uint32(10000))

	return NewStrategy(trigger, decoyThenReal(tamperSeq), nil)
}

// IranDPIStrategy2 - Alternative Iranian bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:8}-|"
// Description: Fragment HTTP requests to evade content filtering
func IranDPIStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Iran DPI Strategy 2",
			"description": "Fragment HTTP requests",
		},
	}

	// Outbound: fragment at offset 8 (after "GET / HT")
	frag := NewFragmentPrimitive(8, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// RussiaTSPUStrategy1 - Effective against Russian TSPU DPI
// Strategy: "[TCP:flags:S]-duplicate(tamper{TTL:8})-|"
// Description: Low TTL duplicate to exhaust TSPU state tracking
func RussiaTSPUStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 1",
			"description": "Low TTL SYN duplicate",
		},
	}

	// Outbound: a TTL=8 decoy SYN, then the real SYN untouched
	tamperTTL := NewTamperPrimitive("ttl", uint8(8))

	return NewStrategy(trigger, decoyThenReal(tamperTTL), nil)
}

// RussiaTSPUStrategy2 - Alternative TSPU bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:1}-|"
// Description: Fragment at offset 1 to break SNI detection
func RussiaTSPUStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 2",
			"description": "Single-byte fragment for SNI evasion",
		},
	}

	// Outbound: fragment at offset 1
	frag := NewFragmentPrimitive(1, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// RussiaTSPUStrategy3 - Advanced TSPU bypass
// Strategy: "[TCP:flags:PA]-duplicate(tamper{flags:R})-|"
// Description: Send RST duplicate to poison TSPU flow table
func RussiaTSPUStrategy3() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 3",
			"description": "RST poisoning",
		},
	}

	// Outbound: an RST decoy, then the real PSH-ACK untouched
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagRST))

	return NewStrategy(trigger, decoyThenReal(tamperFlags), nil)
}

// TurkeyDPIStrategy1 - Effective against Turkish DPI
// Strategy: "[TCP:flags:S]-duplicate(tamper{seq:0})-|"
// Description: Zero sequence number on duplicate to confuse DPI
func TurkeyDPIStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Turkey DPI Strategy 1",
			"description": "Zero sequence number confusion",
		},
	}

	// Outbound: a zero-seq decoy, then the real SYN untouched
	tamperSeq := NewTamperPrimitive("seq", uint32(0))

	return NewStrategy(trigger, decoyThenReal(tamperSeq), nil)
}

// GhostDecoyRealStrategy - ghost, then benign-Host decoy, then the real request
// Strategy: "[TCP:payload:Host: <forbidden>]-duplicate{2}-truncate{1}-corrupt|load{...}-corrupt|send"
// Inbound: "[TCP:flags:&RST]-drop-|"
//
// Description: the HTTP-Host triple from the CircumVolve TCP/IP set.
//
// Three packets at the same sequence number, in this order:
//
//  1. a one-byte ghost with a bad checksum, so a DPI that parses the first
//     bytes of a flow commits to a one-byte body;
//  2. a full-length decoy whose Host header names an allowed domain, also with
//     a bad checksum, so endpoints drop it but a checksum-blind middlebox
//     classifies the flow as allowed;
//  3. the real request, untouched and valid, which the server actually reads.
//
// The decoy keeps the original length: the allowed name is padded or truncated
// to the forbidden name's length, so every offset after the Host header is
// unchanged and the decoy stays a plausible request.
//
// Inbound, all RSTs are dropped. A censor that decides "blocked" kills the flow
// with a forged RST; swallowing it lets the connection that the server is still
// serving survive. The cost is that a genuinely reset connection lingers until
// its own timeout.
//
// The inbound half needs the injector's second queue (NewInjectorDuplex) and
// the operator's INPUT rule; without them only the outbound triple runs.
func GhostDecoyRealStrategy(forbidden, allowed string) *Strategy {
	if forbidden == "" {
		forbidden = "pornhub.com"
	}
	if allowed == "" {
		allowed = "example.com"
	}
	// Same-length replacement keeps the decoy byte-for-byte aligned with the
	// real request outside the hostname.
	replacement := make([]byte, len(forbidden))
	for i := range replacement {
		replacement[i] = 'x'
	}
	copy(replacement, allowed)

	outTrigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte("Host: " + forbidden),
		Metadata: map[string]string{
			"name":        "Ghost + Host decoy + real",
			"description": "One-byte bad-checksum ghost, benign-Host decoy, then the real request; inbound RSTs dropped",
		},
	}
	inTrigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Operator: "&",
		Value:    uint8(TCPFlagRST),
	}

	tree := NewActionTree(NewDuplicatePrimitive(2))
	tree.AddBranch(NewActionTree(NewTruncatePrimitive(1), &CorruptChecksumPrimitive{}))
	tree.AddBranch(NewActionTree(NewLoadTamperPrimitive([]byte(forbidden), replacement), &CorruptChecksumPrimitive{}))
	tree.AddBranch(NewActionTree(&SendPrimitive{}))

	return NewDuplexStrategy(outTrigger, tree, inTrigger, NewActionTree(&DropPrimitive{}))
}

// HostHeaderSplitStrategy - split the request before the Host header
// Strategy: "[TCP:payload:Host:]-fragment-at{Host:,0}-|"
// Inbound: "[TCP:]-drop-rst-drop-early-small{120,4}-|"
//
// Description: the second China recipe from the CircumVolve TCP/IP set.
//
// The first request segment is cut in two: everything up to the Host header,
// then the rest including the forbidden Host. A DPI that parses only the first
// segment of a flow sees a request with no Host and has nothing to match on; the
// server reassembles the two in-order segments into the original request.
//
// Inbound, forged RSTs are dropped and so are small PSH+ACK segments in the
// first four server packets - an injected 302 or one-line 404 arrives exactly
// like that. The window is per flow and the primitive is stateful, so a small
// real response inside the window is dropped too and recovered by the server's
// retransmission.
//
// The inbound half needs the injector's second queue and the operator's INPUT
// rule; without them only the split runs.
func HostHeaderSplitStrategy() *Strategy {
	outTrigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte("Host:"),
		Metadata: map[string]string{
			"name":        "Host-header split",
			"description": "Split the first request before Host; inbound RSTs and small early block pages dropped",
		},
	}
	inTrigger := Trigger{Protocol: "TCP"}

	outbound := NewActionTree(NewFragmentAtPrimitive([]byte("Host:"), 0))
	inbound := NewActionTree(&RSTDropPrimitive{}, NewEarlySmallDropPrimitive(120, 4))

	return NewDuplexStrategy(outTrigger, outbound, inTrigger, inbound)
}

// BenignHostRaceStrategy - benign-Host twin first, real request 8 ms later
// Strategy: "[TCP:payload:Host: <forbidden>]-duplicate-load{...}-|delay{8ms}-|"
// Inbound: "[TCP:]-drop-rst-|"
//
// Description: the third China recipe from the CircumVolve TCP/IP set.
//
// A copy of the request with the Host header rewritten to an allowed domain is
// sent first, fully valid; the real request follows 8 ms later at the same
// sequence number. Both are valid, so the server accepts whichever arrives first
// and discards the other as a duplicate - the connection still works even if the
// decoy wins the race. The point is to make the censor's "first request per flow
// wins" reassembly log the benign Host.
//
// The difference from GhostDecoyRealStrategy is that nothing here is corrupted:
// the decoy is meant to be accepted, not discarded. That makes it safe on paths
// where the endpoint validates checksums strictly, and it means the strategy
// cannot be defeated by a checksum check alone.
//
// Inbound, all RSTs are dropped so a forged reset does not kill a flow the
// server is still serving. Needs the injector's inbound queue and the operator's
// INPUT rule; without them only the race runs.
func BenignHostRaceStrategy(forbidden, allowed string) *Strategy {
	if forbidden == "" {
		forbidden = "pornhub.com"
	}
	if allowed == "" {
		allowed = "example.com"
	}
	replacement := make([]byte, len(forbidden))
	for i := range replacement {
		replacement[i] = 'x'
	}
	copy(replacement, allowed)

	outTrigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte("Host: " + forbidden),
		Metadata: map[string]string{
			"name":        "Benign-Host race",
			"description": "Valid benign-Host twin first, real request 8 ms later; inbound RSTs dropped",
		},
	}
	inTrigger := Trigger{Protocol: "TCP"}

	tree := NewActionTree(NewDuplicatePrimitive(1))
	tree.AddBranch(NewActionTree(NewLoadTamperPrimitive([]byte(forbidden), replacement)))
	tree.AddBranch(NewActionTree(NewDelayPrimitive(8*time.Millisecond), &SendPrimitive{}))

	return NewDuplexStrategy(outTrigger, tree, inTrigger, NewActionTree(&RSTDropPrimitive{}))
}

// SNIPunycodeDecoyStrategy - punycode-rewritten SNI decoy, then the real hello
// Strategy: "[TCP:payload:0x1603]-duplicate-sni{xn--}-corrupt|send"
// Inbound: "[TCP:]-drop-rst-|"
//
// Description: own hypothesis, not from a CircumVolve recipe.
//
// The decoy carries the same ClientHello with the SNI replaced by
// `xn--`+hex(original) and a bad checksum, so the server discards it and the
// censor still parses it. A DPI that matches the SNI as a literal string sees a
// name it has no rule for; one that decodes punycode sees the hex blob, not the
// domain. The real hello follows untouched, so the donor handshake and the
// certificate the server serves are unaffected.
//
// The decoy is corrupted on purpose for exactly that reason: the server must not
// accept it, or it would try to resolve the punycode name as a donor.
func SNIPunycodeDecoyStrategy() *Strategy {
	outTrigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte{0x16, 0x03},
		Metadata: map[string]string{
			"name":        "SNI punycode decoy",
			"description": "Bad-checksum decoy with punycode SNI, then the real ClientHello; inbound RSTs dropped",
		},
	}
	inTrigger := Trigger{Protocol: "TCP"}

	tree := NewActionTree(NewDuplicatePrimitive(1))
	tree.AddBranch(NewActionTree(NewSNIRewritePrimitive("xn--"), &CorruptChecksumPrimitive{}))
	tree.AddBranch(NewActionTree(&SendPrimitive{}))

	return NewDuplexStrategy(outTrigger, tree, inTrigger, NewActionTree(&RSTDropPrimitive{}))
}

// MinimalRSTOverlapStrategy - bare-RST filter, tiny overlap on HTTP requests
// Strategy: "[TCP:payload:HTTP/1.]-overlap-split{20,2,24}-|"
// Inbound: "[TCP:]-drop-bare-rst-|"
//
// Description: the Pakistan/Iran minimal-desync recipe from the CircumVolve
// TCP/IP set (pakistan/17ff6086, with the same inbound filter as iran/0367d00b
// and iran/d5037eed).
//
// Only the first HTTP request is split, and only by a couple of bytes: a 20-byte
// prefix, then the rest starting two bytes before the prefix ends. The server
// reassembles it into the original request, but a DPI that resolves overlaps
// naively sees the request line twice and can mis-locate the Host header. The
// split is confined to HTTP so other protocols on the same tunnel are untouched.
//
// Inbound, only payload-less RSTs are dropped. That is narrower than
// GhostDecoyRealStrategy, which drops every RST: a reset that carries data is
// kept here.
func MinimalRSTOverlapStrategy() *Strategy {
	outTrigger := Trigger{
		Protocol: "TCP",
		Field:    "payload",
		Operator: "contains",
		Value:    []byte("HTTP/1."),
		Metadata: map[string]string{
			"name":        "Minimal RST filter + HTTP overlap",
			"description": "Two-byte overlap on HTTP requests; only bare inbound RSTs dropped",
		},
	}
	inTrigger := Trigger{Protocol: "TCP"}

	outbound := NewActionTree(NewOverlapSplitPrimitive(20, 2, 24))
	inbound := NewActionTree(&BareRSTDropPrimitive{})

	return NewDuplexStrategy(outTrigger, outbound, inTrigger, inbound)
}

// GenericFragmentStrategy - Generic fragmentation bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:10}-|"
// Description: Fragment payload to evade basic keyword detection
// GenericFragmentStrategy splits the first payload-bearing segment.
func GenericFragmentStrategy() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Generic Fragment Strategy",
			"description": "Basic payload fragmentation",
		},
	}

	// Outbound: fragment at offset 10
	frag := NewFragmentPrimitive(10, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// GenericDuplicateStrategy - Generic duplicate bypass
// Strategy: "[TCP:flags:S]-duplicate-|"
// Description: Simple SYN duplication to exhaust middlebox resources
func GenericDuplicateStrategy() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Generic Duplicate Strategy",
			"description": "Simple SYN duplication",
		},
	}

	// Outbound: duplicate packet
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(dup)

	return NewStrategy(trigger, outbound, nil)
}

// GetAllStrategies returns all pre-discovered Geneva strategies
func GetAllStrategies() map[string]*Strategy {
	return map[string]*Strategy{
		"china_gfw_1":         ChinaGFWStrategy1(),
		"china_gfw_2":         ChinaGFWStrategy2(),
		"china_gfw_3":         ChinaGFWStrategy3(),
		"iran_dpi_1":          IranDPIStrategy1(),
		"iran_dpi_2":          IranDPIStrategy2(),
		"russia_tspu_1":       RussiaTSPUStrategy1(),
		"russia_tspu_2":       RussiaTSPUStrategy2(),
		"russia_tspu_3":       RussiaTSPUStrategy3(),
		"turkey_dpi_1":        TurkeyDPIStrategy1(),
		"ghost_decoy_real":    GhostDecoyRealStrategy("", ""),
		"host_header_split":   HostHeaderSplitStrategy(),
		"benign_host_race":    BenignHostRaceStrategy("", ""),
		"sni_punycode_decoy":  SNIPunycodeDecoyStrategy(),
		"minimal_rst_overlap": MinimalRSTOverlapStrategy(),
		"generic_fragment":    GenericFragmentStrategy(),
		"generic_dup":         GenericDuplicateStrategy(),
	}
}

// GetStrategyByName returns a specific strategy by name
func GetStrategyByName(name string) *Strategy {
	strategies := GetAllStrategies()
	return strategies[name]
}

// GetStrategiesByCountry returns strategies for a specific country
func GetStrategiesByCountry(country string) []*Strategy {
	all := GetAllStrategies()
	var result []*Strategy

	switch country {
	case "china", "cn":
		result = append(result,
			all["china_gfw_1"],
			all["china_gfw_2"],
			all["china_gfw_3"],
			all["ghost_decoy_real"],
			all["host_header_split"],
			all["benign_host_race"],
		)
	case "iran", "ir":
		result = append(result,
			all["iran_dpi_1"],
			all["iran_dpi_2"],
			all["sni_punycode_decoy"],
			all["minimal_rst_overlap"],
		)
	case "russia", "ru":
		result = append(result,
			all["russia_tspu_1"],
			all["russia_tspu_2"],
			all["russia_tspu_3"],
		)
	case "turkey", "tr":
		result = append(result,
			all["turkey_dpi_1"],
			all["sni_punycode_decoy"],
		)
	default:
		// Return generic strategies
		result = append(result,
			all["generic_fragment"],
			all["generic_dup"],
		)
	}

	return result
}

// GetSuccessRate reports how often a strategy is expected to work.
//
// It always returns "unmeasured". Every strategy here used to carry a hardcoded
// percentage in its metadata - 85% for Russia TSPU 1, 90% for TSPU 2, 75% for
// China GFW 1 - with nothing behind any of them: no capture, no run against a
// live DPI, no cited source. They also described the packet-level behaviour as
// it was before decoyThenReal, which tampered the real packet along with the
// decoy and so could not have worked at all.
//
// The numbers are removed rather than corrected, because correcting them needs
// a measurement nobody has made. Callers that print this string now say so.
func (s *Strategy) GetSuccessRate() string {
	return "unmeasured"
}

// GetName returns the strategy name
func (s *Strategy) GetName() string {
	if s.Trigger.Metadata != nil {
		return s.Trigger.Metadata["name"]
	}
	return "unnamed strategy"
}

// GetDescription returns the strategy description
func (s *Strategy) GetDescription() string {
	if s.Trigger.Metadata != nil {
		return s.Trigger.Metadata["description"]
	}
	return "no description"
}
