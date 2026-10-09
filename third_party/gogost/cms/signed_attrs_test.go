package cms

import "testing"

func TestSignedAttributesRequireCanonicalOrderAndUniqueOIDs(t *testing.T) {
	contentType := makeAttribute(oidContentType, derOID(oidData))
	messageDigest := makeAttribute(oidMessageDigest, derWrap(0x04, make([]byte, 32)))
	_, sorted, _, err := readExpected(derSet(contentType, messageDigest), 0x31)
	if err != nil {
		t.Fatal(err)
	}
	first, _, rest, err := readExpected(sorted, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	second, _, tail, err := readExpected(rest, 0x30)
	if err != nil || len(tail) != 0 {
		t.Fatalf("attributes: %v", err)
	}
	for _, tc := range []struct {
		name  string
		attrs []byte
		valid bool
	}{
		{"sorted", sorted, true},
		{"reversed", append(append([]byte(nil), second...), first...), false},
		{"duplicate", append(append(append([]byte(nil), first...), first...), second...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &SignerInfo{signedAttrs: derWrap(0x31, tc.attrs)}
			err := parseSignedAttrs(info, tc.attrs, oidData)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
