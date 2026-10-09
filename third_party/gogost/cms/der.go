package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math"
	"sort"
)

// The CMS reader deliberately handles only the ASN.1 forms used by this
// package. Limits are checked before slicing or allocating attacker data.
const (
	maxCMSSize         = 128 << 20
	maxCMSSigners      = 32
	maxCMSCertificates = 64
	maxCMSDepth        = 16
)

var errMalformedDER = errors.New("gogost/cms: Некорректный DER")

func readDER(in []byte) (tag byte, full, value, rest []byte, err error) {
	if len(in) < 2 || in[0]&0x1f == 0x1f {
		return 0, nil, nil, nil, errMalformedDER
	}
	n := int(in[1])
	header := 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 4 || len(in) < 2+count || in[2] == 0 {
			return 0, nil, nil, nil, errMalformedDER
		}
		n = 0
		for _, b := range in[2 : 2+count] {
			n = n<<8 | int(b)
		}
		if n < 128 {
			return 0, nil, nil, nil, errMalformedDER
		}
		header += count
	}
	if n > maxCMSSize || n > len(in)-header {
		return 0, nil, nil, nil, errMalformedDER
	}
	end := header + n
	return in[0], in[:end], in[header:end], in[end:], nil
}

func readExpected(in []byte, want byte) (full, value, rest []byte, err error) {
	tag, full, value, rest, err := readDER(in)
	if err != nil || tag != want {
		return nil, nil, nil, errMalformedDER
	}
	return full, value, rest, nil
}

// readBER additionally accepts constructed indefinite-length values. It
// leaves their contents in the original input buffer and bounds recursion.
func readBER(in []byte, depth int) (tag byte, full, value, rest []byte, err error) {
	if depth > maxCMSDepth || len(in) < 2 || in[0]&0x1f == 0x1f {
		return 0, nil, nil, nil, errMalformedDER
	}
	if in[1] != 0x80 {
		return readDER(in)
	}
	if in[0]&0x20 == 0 {
		return 0, nil, nil, nil, errMalformedDER
	}
	offset := 2
	for {
		if offset+2 > len(in) || offset > maxCMSSize {
			return 0, nil, nil, nil, errMalformedDER
		}
		if in[offset] == 0 && in[offset+1] == 0 {
			return in[0], in[:offset+2], in[2:offset], in[offset+2:], nil
		}
		_, child, _, _, e := readBER(in[offset:], depth+1)
		if e != nil {
			return 0, nil, nil, nil, e
		}
		offset += len(child)
	}
}

func readExpectedBER(in []byte, want byte) (full, value, rest []byte, err error) {
	tag, full, value, rest, err := readBER(in, 0)
	if err != nil || tag != want {
		return nil, nil, nil, errMalformedDER
	}
	return full, value, rest, nil
}

func octetSegments(tag byte, value []byte, depth int, dst [][]byte) ([][]byte, error) {
	if depth > maxCMSDepth || len(dst) > 1<<20 {
		return nil, errMalformedDER
	}
	if tag == 0x04 || tag == 0x80 {
		return append(dst, value), nil
	}
	if tag != 0x24 && tag != 0xa0 {
		return nil, errMalformedDER
	}
	for len(value) != 0 {
		childTag, _, childValue, rest, err := readBER(value, depth+1)
		if err != nil {
			return nil, err
		}
		dst, err = octetSegments(childTag, childValue, depth+1, dst)
		if err != nil {
			return nil, err
		}
		value = rest
	}
	return dst, nil
}

func derLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	ret := make([]byte, 1+len(buf)-i)
	ret[0] = 0x80 | byte(len(buf)-i)
	copy(ret[1:], buf[i:])
	return ret
}

func derWrap(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	length := derLength(n)
	out := make([]byte, 1+len(length), 1+len(length)+n)
	out[0] = tag
	copy(out[1:], length)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func derSet(parts ...[]byte) []byte {
	sort.Slice(parts, func(i, j int) bool { return bytes.Compare(parts[i], parts[j]) < 0 })
	return derWrap(0x31, parts...)
}

func derOID(oid asn1.ObjectIdentifier) []byte {
	out, _ := asn1.Marshal(oid)
	return out
}

func parseOID(in []byte) (asn1.ObjectIdentifier, []byte, error) {
	_, value, rest, err := readExpected(in, 0x06)
	if err != nil {
		return nil, nil, err
	}
	if len(value) == 0 {
		return nil, nil, errMalformedDER
	}
	// Decode OIDs directly: encoding/asn1.Unmarshal allocates a temporary
	// len(value)+1 slice and reflection state for every CMS algorithm and
	// attribute. Two short passes allocate only the exact result slice.
	components := 0
	for offset := 0; offset < len(value); components++ {
		_, next, e := readOIDComponent(value, offset)
		if e != nil {
			return nil, nil, e
		}
		offset = next
	}
	oid := make(asn1.ObjectIdentifier, components+1)
	first, offset, _ := readOIDComponent(value, 0)
	switch {
	case first < 40:
		oid[0], oid[1] = 0, first
	case first < 80:
		oid[0], oid[1] = 1, first-40
	default:
		oid[0], oid[1] = 2, first-80
	}
	for index := 2; offset < len(value); index++ {
		oid[index], offset, _ = readOIDComponent(value, offset)
	}
	return oid, rest, nil
}

func readOIDComponent(value []byte, offset int) (int, int, error) {
	var number uint64
	for shifted := 0; shifted < 5; shifted++ {
		if offset >= len(value) || shifted == 0 && value[offset] == 0x80 {
			return 0, 0, errMalformedDER
		}
		b := value[offset]
		offset++
		number = number<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			if number > math.MaxInt32 {
				return 0, 0, errMalformedDER
			}
			return int(number), offset, nil
		}
	}
	return 0, 0, errMalformedDER
}

func parseSmallInt(in []byte) (int, []byte, error) {
	full, _, rest, err := readExpected(in, 0x02)
	if err != nil {
		return 0, nil, err
	}
	var value int
	if _, err = asn1.Unmarshal(full, &value); err != nil || value < 0 {
		return 0, nil, errMalformedDER
	}
	return value, rest, nil
}

func parseAlgorithm(in []byte) (asn1.ObjectIdentifier, []byte, error) {
	_, body, rest, err := readExpected(in, 0x30)
	if err != nil {
		return nil, nil, err
	}
	oid, tail, err := parseOID(body)
	if err != nil {
		return nil, nil, err
	}
	// GOST algorithm identifiers omit parameters. A NULL is accepted for
	// older encoders, but arbitrary parameters are never ignored.
	if len(tail) != 0 && !bytes.Equal(tail, []byte{0x05, 0x00}) {
		return nil, nil, errMalformedDER
	}
	return oid, rest, nil
}

func algorithmDER(oid asn1.ObjectIdentifier) []byte { return derWrap(0x30, derOID(oid)) }
