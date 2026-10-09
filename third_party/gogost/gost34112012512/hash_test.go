package gost34112012512_test

import (
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

const (
	compatibilityPassword = "Пароль-совместимость-2026"
	compatibilityHash     = "$gy$Tj0zMjc2OCxyPTgscD0xLGtleUxlbj02NA==$cGFzczEyMzRzYWx0NDU2Nzg=$tXAVthD7D+eWHq/1imo1q1o5NwsNz069xRIpkGlwQtDZjRkFWpO9XU4Tk8KeoUfr1CAj/ebKPJcC5a9OaYiuLA=="
)

func TestVerifyGostYescryptHashCompatibility(t *testing.T) {
	digest, err := gost34112012512.GostYescrypt(
		[]byte("pass1234salt45678"),
		[]byte(compatibilityPassword),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(digest)

	formatted := gost34112012512.FormatGostYescryptHash([]byte("pass1234salt45678"), digest)
	if formatted != compatibilityHash {
		t.Fatalf("wire format changed:\n got: %s\nwant: %s", formatted, compatibilityHash)
	}

	match, err := gost34112012512.VerifyGostYescryptHash(
		formatted,
		[]byte(compatibilityPassword),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("v2.7.0 compatibility hash did not match")
	}
}

func TestVerifyGostYescryptHashRejectsMalformed(t *testing.T) {
	match, err := gost34112012512.VerifyGostYescryptHash("not-a-hash", []byte("password"))
	if err == nil {
		t.Fatal("malformed hash returned nil error")
	}
	if match {
		t.Fatal("malformed hash matched")
	}
}
