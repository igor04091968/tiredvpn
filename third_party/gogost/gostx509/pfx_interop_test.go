package gostx509_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestCompetitorPasswordPFX(t *testing.T) {
	der, err := os.ReadFile(filepath.Join("testdata", "competitor-pfx", "password.p12"))
	if err != nil {
		t.Fatal(err)
	}
	key, cert, _, err := gostx509.ParsePFX(der, "interop-password")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || cert == nil {
		t.Fatal("missing key or certificate")
	}
	if _, _, _, err := gostx509.ParsePFX(der, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
}
