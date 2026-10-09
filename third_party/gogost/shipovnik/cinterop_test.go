//go:build cinterop

package shipovnik

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestQAPPCrossVerify expects QAPP-compatible helper executables built from
// testdata/qapp_interop.c. SHIPOVNIK_QAPP_REFERENCE must use DELTA=219 and
// SHIPOVNIK_QAPP_ARTICLE70 must use a test build with DELTA=137.
func TestQAPPCrossVerify(t *testing.T) {
	tests := []struct {
		name   string
		scheme Scheme
		env    string
	}{
		{"Reference", Reference(), "SHIPOVNIK_QAPP_REFERENCE"},
		{"Article70", Article70(), "SHIPOVNIK_QAPP_ARTICLE70"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			helper := os.Getenv(test.env)
			if helper == "" {
				t.Skipf("%s is not set", test.env)
			}
			directory := t.TempDir()
			private := fixedPrivateKey(t, test.scheme)
			public := private.Public().(*PublicKey)
			message := []byte("QAPP/Go cross-verification " + test.name)
			paths := map[string]string{
				"sk":  filepath.Join(directory, "private.bin"),
				"pk":  filepath.Join(directory, "public.bin"),
				"msg": filepath.Join(directory, "message.bin"),
				"go":  filepath.Join(directory, "go-signature.bin"),
				"c":   filepath.Join(directory, "c-signature.bin"),
				"cpk": filepath.Join(directory, "c-public.bin"),
			}
			mustWrite := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			mustWrite(paths["sk"], private.Bytes())
			mustWrite(paths["pk"], public.Bytes())
			mustWrite(paths["msg"], message)

			goSignature, err := private.SignMessage(newDeterministicReader("go-to-qapp-"+test.name), message, &Options{Workers: 4})
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(paths["go"], goSignature)
			runInterop(t, helper, "verify", paths["pk"], paths["msg"], paths["go"])

			runInterop(t, helper, "sign", paths["sk"], paths["msg"], paths["c"], paths["cpk"])
			cPublic, err := os.ReadFile(paths["cpk"])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cPublic, public.Bytes()) {
				t.Fatal("C and Go derived different public keys")
			}
			cSignature, err := os.ReadFile(paths["c"])
			if err != nil {
				t.Fatal(err)
			}
			valid, err := public.Verify(message, cSignature, &Options{Workers: 4})
			if err != nil || !valid {
				t.Fatalf("Go rejected C signature: valid=%v err=%v", valid, err)
			}
		})
	}
}

func runInterop(t testing.TB, executable string, arguments ...string) {
	t.Helper()
	command := exec.Command(executable, arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", executable, arguments, err, fmt.Sprintf("%s", output))
	}
}
