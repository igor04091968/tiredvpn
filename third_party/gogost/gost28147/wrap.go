package gost28147

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
)

func WrapGost(ukm, kek, cek []byte) []byte {
	c := NewCipher(kek, &SboxIdGost2814789CryptoProAParamSet)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		panic(err)
	}
	_, err = mac.Write(cek)
	if err != nil {
		panic(err)
	}
	cekMac := mac.Sum(nil)
	cekEnc := make([]byte, 32)
	c.NewECBEncrypter().CryptBlocks(cekEnc, cek)
	return bytes.Join([][]byte{ukm, cekEnc, cekMac}, nil)
}

func UnwrapGost(kek, data []byte) []byte {
	ukm, data := data[:8], data[8:]
	cekEnc, cekMac := data[:KeySize], data[KeySize:]
	c := NewCipher(kek, &SboxIdGost2814789CryptoProAParamSet)
	cek := make([]byte, 32)
	c.NewECBDecrypter().CryptBlocks(cek, cekEnc)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		panic(err)
	}
	_, err = mac.Write(cek)
	if err != nil {
		panic(err)
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), cekMac) != 1 {
		return nil
	}
	return cek
}

func DiversifyCryptoPro(kek, ukm []byte) []byte {
	return DiversifyCryptoProWithSbox(kek, ukm, &SboxIdGost2814789CryptoProAParamSet)
}

// DiversifyCryptoProWithSbox applies RFC 4357 KEK diversification using the
// selected GOST 28147 parameter set. It updates kek in place.
func DiversifyCryptoProWithSbox(kek, ukm []byte, sbox *Sbox) []byte {
	out := kek
	var c Cipher
	for i := range 8 {
		var s1, s2 uint64
		for j := range 8 {
			k := binary.LittleEndian.Uint32(out[j*4 : j*4+4])
			if (ukm[i]>>j)&1 > 0 {
				s1 += uint64(k)
			} else {
				s2 += uint64(k)
			}
		}
		var iv [8]byte
		binary.LittleEndian.PutUint32(iv[:4], uint32(s1%(1<<32)))
		binary.LittleEndian.PutUint32(iv[4:], uint32(s2%(1<<32)))
		c.SetKey(out, sbox)
		c.NewCFBEncrypter(iv[:]).XORKeyStream(out, out)
	}
	return out
}

func UnwrapCryptoPro(kek, data []byte) []byte {
	return UnwrapGost(DiversifyCryptoPro(kek, data[:8]), data)
}
