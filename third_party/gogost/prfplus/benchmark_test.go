package prfplus

import "testing"

var benchPRFPlusOut []byte

func benchPRFPlusKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*17 + 9)
	}
	return key
}

func benchPRFPlusSalt() []byte {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i*19 + 3)
	}
	return salt
}

func BenchmarkPRFPlus(b *testing.B) {
	key := benchPRFPlusKey()
	salt := benchPRFPlusSalt()
	for _, tc := range []struct {
		name string
		prf  PRFForPlus
	}{
		{"256", NewPRFIPsecPRFPlusGOSTR34112012256(key)},
		{"512", NewPRFIPsecPRFPlusGOSTR34112012512(key)},
	} {
		for _, size := range []struct {
			name string
			n    int
		}{
			{"64B", 64},
			{"1KiB", 1024},
			{"16KiB", 16 * 1024},
		} {
			out := make([]byte, size.n)
			b.Run(tc.name+"/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					PRFPlus(tc.prf, out, salt)
				}
				benchPRFPlusOut = out
			})
		}
	}
}
