package profiles_test

import (
	"bytes"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/profiles"
)

func TestProfiles(t *testing.T) {
	key := make([]byte, gost3412128.KeySize)
	iv := make([]byte, gost3412128.BlockSize/2)

	stream, err := profiles.FileEncryptionKuznechikCTRACPKM(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("file payload")
	ciphertext, err := stream.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := stream.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("CTR-ACPKM profile round-trip mismatch")
	}

	aead, err := profiles.MessageEncryptionMGM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gost3412128.BlockSize)
	sealed, err := aead.Seal(nil, nonce, plaintext, []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := aead.Open(nil, nonce, sealed, []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("MGM profile round-trip mismatch")
	}

}
