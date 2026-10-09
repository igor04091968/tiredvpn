package cms_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/cms"
)

func TestOpenSSLGOSTCMS(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "openssl-gost-cms", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	content := read("content.txt")
	for _, tc := range []struct {
		name     string
		detached bool
	}{{"attached.p7m", false}, {"detached.p7s", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := cms.ParseSignedData(read(tc.name))
			if err != nil {
				t.Fatal(err)
			}
			if sd.Detached != tc.detached || len(sd.Signers) != 1 {
				t.Fatal("unexpected SignedData")
			}
			var detached []byte
			if tc.detached {
				detached = content
			}
			result, err := sd.Verify(detached)
			if err != nil || len(result) != 1 || result[0].Err != nil {
				t.Fatalf("signature: %v %v", result, err)
			}
			if !tc.detached && string(sd.Content) != string(content) {
				t.Fatal("attached content mismatch")
			}
			if tc.detached {
				changed, err := sd.Verify([]byte("wrong"))
				if err == nil && len(changed) == 1 && changed[0].Err == nil {
					t.Fatal("tampering accepted")
				}
			}
		})
	}
}
