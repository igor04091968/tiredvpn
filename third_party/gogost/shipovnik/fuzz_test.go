package shipovnik

import "testing"

func FuzzVerify(f *testing.F) {
	private := make([]byte, PrivateKeySize)
	for bit := 0; bit < SecretWeight; bit++ {
		setBit(private, bit)
	}
	key, err := Article70().NewPrivateKey(private)
	if err != nil {
		f.Fatal(err)
	}
	public := key.Public().(*PublicKey)
	f.Add([]byte("message"), []byte{})
	f.Add([]byte{}, make([]byte, Article70().MinSignatureSize()))
	f.Fuzz(func(t *testing.T, message, signature []byte) {
		_, _ = public.Verify(message, signature, &Options{Workers: 1})
	})
}
