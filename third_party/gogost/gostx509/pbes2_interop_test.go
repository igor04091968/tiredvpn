package gostx509

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
)

// The fixture crosses three CryptoPro key-meshing sections.
func TestCompetitorMeshedPBES2(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "competitor-pbes2", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var algorithm pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(read("algorithm.der"), &algorithm); err != nil || len(rest) != 0 {
		t.Fatalf("algorithm: %v", err)
	}
	plain, err := decryptPBES2(algorithm, read("cipher.bin"), "interop-password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, read("plain.bin")) {
		t.Fatal("meshed CFB plaintext mismatch")
	}
}
