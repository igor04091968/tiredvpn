package geneva

import (
	"errors"
	"fmt"
)

// Strategy represents a Geneva evasion strategy
// Format: "trigger:outbound-tree,inbound-tree"
// Example: "[TCP:flags:S]-drop-|" means drop SYN packets
type Strategy struct {
	Trigger      Trigger
	OutboundTree *ActionTree
	InboundTree  *ActionTree
	// InboundTrigger, when set, replaces Trigger for inbound packets. A single
	// trigger cannot describe both directions when they look different - an
	// outbound HTTP request and an inbound forged RST share no field.
	InboundTrigger *Trigger
}

// Trigger defines when to apply a strategy
type Trigger struct {
	Protocol string            // "TCP", "UDP"
	Field    string            // "flags", "seq", "payload"
	Value    interface{}       // Expected value
	Operator string            // "==", "!=", "contains"
	Metadata map[string]string // Additional metadata
}

// ActionTree represents a tree of Geneva actions
type ActionTree struct {
	Root     *ActionNode
	Branches []*ActionTree
}

// ActionNode represents a single action in the tree
type ActionNode struct {
	Primitive Primitive
	Next      *ActionNode
}

// NewStrategy creates a new Geneva strategy
func NewStrategy(trigger Trigger, outbound, inbound *ActionTree) *Strategy {
	return &Strategy{
		Trigger:      trigger,
		OutboundTree: outbound,
		InboundTree:  inbound,
	}
}

// NewDuplexStrategy creates a strategy with separate inbound and outbound
// triggers, for the strategies that act on both directions.
func NewDuplexStrategy(outTrigger Trigger, outbound *ActionTree, inTrigger Trigger, inbound *ActionTree) *Strategy {
	return &Strategy{
		Trigger:        outTrigger,
		OutboundTree:   outbound,
		InboundTree:    inbound,
		InboundTrigger: &inTrigger,
	}
}

// Match checks if the outbound trigger matches the packet
func (s *Strategy) Match(packet []byte) (bool, error) {
	return matchTrigger(&s.Trigger, packet)
}

func matchTrigger(t *Trigger, packet []byte) (bool, error) {
	if len(packet) < 20 {
		return false, errors.New("packet too short")
	}

	// Parse IP header
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	protocol := packet[9]

	// Check protocol match
	if t.Protocol == "TCP" && protocol != 6 {
		return false, nil
	}
	if t.Protocol == "UDP" && protocol != 17 {
		return false, nil
	}

	// Check field match
	switch t.Field {
	case "flags":
		if protocol != 6 {
			return false, nil
		}
		flags, err := ParseTCPFlags(packet)
		if err != nil {
			return false, err
		}

		expectedFlags, ok := t.Value.(uint8)
		if !ok {
			return false, errors.New("invalid trigger value for flags")
		}

		switch t.Operator {
		case "==":
			return flags == expectedFlags, nil
		case "!=":
			return flags != expectedFlags, nil
		case "&":
			// Bitwise AND (check if flag is set)
			return (flags & expectedFlags) != 0, nil
		default:
			return flags == expectedFlags, nil
		}

	case "ttl":
		// IP TTL. Numeric comparison so a strategy can say "only packets that
		// still have most of their hop budget" instead of one exact value.
		expectedTTL, ok := t.Value.(uint8)
		if !ok {
			return false, errors.New("invalid trigger value for ttl")
		}
		ttl := packet[8]
		switch t.Operator {
		case "==":
			return ttl == expectedTTL, nil
		case "!=":
			return ttl != expectedTTL, nil
		case "<":
			return ttl < expectedTTL, nil
		case ">":
			return ttl > expectedTTL, nil
		case "<=":
			return ttl <= expectedTTL, nil
		case ">=":
			return ttl >= expectedTTL, nil
		default:
			return ttl == expectedTTL, nil
		}

	case "payload":
		// Check payload content
		if len(packet) < ipHeaderLen+20 {
			return false, nil
		}

		tcpStart := ipHeaderLen
		tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
		payloadStart := tcpStart + tcpHeaderLen

		if len(packet) <= payloadStart {
			return false, nil
		}

		payload := packet[payloadStart:]
		expectedBytes, ok := t.Value.([]byte)
		if !ok {
			return false, errors.New("invalid trigger value for payload")
		}

		if t.Operator == "contains" {
			return contains(payload, expectedBytes), nil
		}

		return false, nil

	default:
		return true, nil // No field check, always match
	}
}

// Apply applies the strategy to a packet
func (s *Strategy) Apply(packet []byte, isOutbound bool) ([]Result, error) {
	trigger := &s.Trigger
	if !isOutbound && s.InboundTrigger != nil {
		trigger = s.InboundTrigger
	}
	match, err := matchTrigger(trigger, packet)
	if err != nil {
		return nil, err
	}

	if !match {
		// No match, return packet unmodified
		return []Result{{Packet: packet}}, nil
	}

	// Apply appropriate tree
	tree := s.OutboundTree
	if !isOutbound {
		tree = s.InboundTree
	}

	if tree == nil {
		return []Result{{Packet: packet}}, nil
	}

	return tree.Execute(packet)
}

// Execute executes the action tree on a packet.
//
// Without branches the root chain's results are returned unchanged. With
// branches the tree follows Geneva's duplicate semantics: result i goes to
// branch i and to no other. A root of duplicate therefore hands branch 0 the
// original packet and branch 1 the copy, which is the only way to manipulate a
// duplicate WITHOUT manipulating the packet it was copied from.
//
// Chaining primitives on the root instead - NewActionTree(dup, tamper) - does
// the opposite: ActionNode.Execute applies every following primitive to every
// result, so the tamper lands on the original as well as on the copy. Every
// packet-level strategy in strategies.go was built that way and consequently
// broke the connection it was meant to protect.
//
// When the root yields more results than there are branches the surplus goes to
// the last branch, so duplicate{count=N} with two branches still means "the
// original down one branch, all N copies down the other".
func (t *ActionTree) Execute(packet []byte) ([]Result, error) {
	return t.execute(Result{Packet: packet})
}

func (t *ActionTree) execute(in Result) ([]Result, error) {
	if t == nil || t.Root == nil {
		return []Result{in}, nil
	}

	// Execute root node
	results, err := t.Root.execute(in)
	if err != nil {
		return nil, err
	}

	if len(t.Branches) == 0 {
		return results, nil
	}

	var finalResults []Result
	for i, res := range results {
		idx := i
		if idx >= len(t.Branches) {
			idx = len(t.Branches) - 1
		}
		branchResults, err := t.Branches[idx].execute(res)
		if err != nil {
			return nil, err
		}
		finalResults = append(finalResults, branchResults...)
	}
	return finalResults, nil
}

// Execute executes the action node (and following nodes) on a packet
func (n *ActionNode) Execute(packet []byte) ([]Result, error) {
	return n.execute(Result{Packet: packet})
}

func (n *ActionNode) execute(in Result) ([]Result, error) {
	if n == nil {
		return []Result{in}, nil
	}

	// Apply current primitive
	results, err := n.Primitive.Apply(in.Packet)
	if err != nil {
		return nil, err
	}

	// A delay already stamped upstream survives a later primitive that does not
	// set one, so DelayPrimitive can sit anywhere in the chain.
	for i := range results {
		if results[i].Delay == 0 {
			results[i].Delay = in.Delay
		}
	}

	// If there's a next node, apply it to all results
	if n.Next != nil {
		var finalResults []Result
		for _, res := range results {
			nextResults, err := n.Next.execute(res)
			if err != nil {
				return nil, err
			}
			finalResults = append(finalResults, nextResults...)
		}
		return finalResults, nil
	}

	return results, nil
}

// String returns a human-readable representation of the strategy
func (s *Strategy) String() string {
	triggerStr := fmt.Sprintf("[%s:%s:%v]", s.Trigger.Protocol, s.Trigger.Field, s.Trigger.Value)

	outboundStr := "send"
	if s.OutboundTree != nil {
		outboundStr = s.OutboundTree.String()
	}

	inboundStr := "send"
	if s.InboundTree != nil {
		inboundStr = s.InboundTree.String()
	}

	return triggerStr + "-" + outboundStr + "," + inboundStr
}

// String returns a string representation of the action tree
func (t *ActionTree) String() string {
	if t == nil || t.Root == nil {
		return "send"
	}

	result := t.Root.String()

	if len(t.Branches) > 0 {
		result += "|"
		for i, branch := range t.Branches {
			if i > 0 {
				result += ","
			}
			result += branch.String()
		}
	}

	return result
}

// String returns a string representation of the action node chain
func (n *ActionNode) String() string {
	if n == nil {
		return ""
	}

	result := n.Primitive.String()

	if n.Next != nil {
		result += "-" + n.Next.String()
	}

	return result
}

// NewActionTree creates a new action tree from a chain of primitives
func NewActionTree(primitives ...Primitive) *ActionTree {
	if len(primitives) == 0 {
		return nil
	}

	// Build chain
	var root, current *ActionNode
	for i, p := range primitives {
		node := &ActionNode{Primitive: p}
		if i == 0 {
			root = node
			current = node
		} else {
			current.Next = node
			current = node
		}
	}

	return &ActionTree{Root: root}
}

// AddBranch adds a branch to the action tree
func (t *ActionTree) AddBranch(branch *ActionTree) {
	if t.Branches == nil {
		t.Branches = []*ActionTree{}
	}
	t.Branches = append(t.Branches, branch)
}

// contains checks if haystack contains needle
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}

	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
