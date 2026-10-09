package cms_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/cms"
)

// The fixture was produced by go-gostcrypto at commit 409be1d9982195558ce16fabd5d0ad20454bee3c.
func TestCompetitorCAdEST(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "competitor-cades-t", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	content := read("content.txt")
	der := read("signed.p7s")
	signed, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.Detached || len(signed.Signers) != 1 {
		t.Fatal("unexpected signed data")
	}
	verified, err := signed.Verify(content)
	if err != nil || len(verified) != 1 || verified[0].Err != nil {
		t.Fatalf("CMS signature: %v %v", verified, err)
	}
	stamps := signed.Signers[0].SignatureTimeStamps
	if len(stamps) != 1 {
		t.Fatalf("timestamps: %d", len(stamps))
	}
	if err := stamps[0].VerifyImprint(signed.Signers[0].Signature); err != nil {
		t.Fatal(err)
	}
	if err := stamps[0].ValidateTSASigner(); err != nil {
		t.Fatal(err)
	}
	results, err := stamps[0].VerifySignatures()
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("timestamp signature: %v %v", results, err)
	}
	if err := stamps[0].VerifyImprint([]byte("tampered signature")); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if changed, err := signed.Verify([]byte("tampered content")); err == nil && len(changed) > 0 && changed[0].Err == nil {
		t.Fatal("tampered content accepted")
	}
}
