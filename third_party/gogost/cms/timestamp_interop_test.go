package cms_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/cms"
)

func TestOpenSSLRFC3161Response(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "openssl-rfc3161", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	message := read("message.txt")
	response := read("response.tsr")
	nonce, ok := new(big.Int).SetString("33CE892906C678B5", 16)
	if !ok {
		t.Fatal("invalid fixture nonce")
	}
	token, err := cms.ParseTimeStampResponse(response, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := token.VerifyImprint(message); err != nil {
		t.Fatal(err)
	}
	if err := token.ValidateTSASigner(); err != nil {
		t.Fatal(err)
	}
	results, err := token.VerifySignatures()
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("OpenSSL TSA signature: %v %v", results, err)
	}
	if err := token.VerifyImprint([]byte("changed")); err == nil {
		t.Fatal("changed imprint accepted")
	}
	if _, err := cms.ParseTimeStampResponse(response, big.NewInt(1)); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}
