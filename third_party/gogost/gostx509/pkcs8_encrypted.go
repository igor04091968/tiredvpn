package gostx509

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

var (
	oidPBES2                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACStreebog512       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 2}
	oidKuznechikCTRACPKMOMAC = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 2, 2}
	oidMagmaCTRACPKMOMAC     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 1, 2}
	oidKuznechikCTRACPKM     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 2, 1}
	oidMagmaCTRACPKM         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 1, 1}
	oidPBES2GOST28147        = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}
	oidPBES2CryptoProA       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
	oidPBES2CryptoProB       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 2}
	oidPBES2CryptoProC       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 3}
	oidPBES2CryptoProD       = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 4}
	oidPBES2TC26Z            = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}
)

const (
	defaultPKCS8Iterations = 10000
	maxPKCS8Iterations     = 1000000
	maxEncryptedPKCS8Size  = 1 << 24
	pkcs8SectionSize       = 1024
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes2Parameters struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Parameters struct {
	Salt           []byte
	IterationCount int
	KeyLength      int `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier
}

type gostPBES2CipherParameters struct{ UKM []byte }

type legacyPBES2CipherParameters struct {
	IV                 []byte
	EncryptionParamSet asn1.ObjectIdentifier
}

// EncryptedPKCS8Options selects the password profile. Zero values select
// authenticated Kuznechik CTR-ACPKM-OMAC and 10000 PBKDF2 iterations.
type EncryptedPKCS8Options struct {
	Magma       bool
	Legacy28147 bool // Unauthenticated PBES2/GOST 28147; use only within an authenticated container.
	Iterations  int
}

// MarshalEncryptedPKCS8PrivateKey encrypts a PKCS #8 key using RFC 9337
// PBES2 with an authenticated Kuznechik or Magma CTR-ACPKM-OMAC scheme.
// Password bytes are interpreted as UTF-8 by the caller.
func MarshalEncryptedPKCS8PrivateKey(key any, password string, opts *EncryptedPKCS8Options) ([]byte, error) {
	return MarshalEncryptedPKCS8PrivateKeyWithRand(rand.Reader, key, password, opts)
}

// MarshalEncryptedPKCS8PrivateKeyWithRand is the entropy-injected form.
func MarshalEncryptedPKCS8PrivateKeyWithRand(random io.Reader, key any, password string, opts *EncryptedPKCS8Options) ([]byte, error) {
	if random == nil {
		return nil, errors.New("gostx509: nil entropy source")
	}
	iterations := defaultPKCS8Iterations
	magma := false
	legacy := false
	if opts != nil {
		if opts.Iterations != 0 {
			iterations = opts.Iterations
		}
		magma = opts.Magma
		legacy = opts.Legacy28147
	}
	if magma && legacy {
		return nil, errors.New("gostx509: conflicting PBES2 cipher options")
	}
	if iterations < 1000 || iterations > maxPKCS8Iterations {
		return nil, errors.New("gostx509: PBKDF2 iteration count out of range")
	}
	plain, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if len(plain) > maxEncryptedPKCS8Size {
		return nil, errors.New("gostx509: PKCS #8 key too large")
	}
	defer clear(plain)
	salt := make([]byte, 32)
	ukm := make([]byte, 16)
	encOID := oidKuznechikCTRACPKMOMAC
	if legacy {
		ukm = make([]byte, gost28147.BlockSize)
		encOID = oidPBES2GOST28147
	} else if magma {
		ukm = make([]byte, 12)
		encOID = oidMagmaCTRACPKMOMAC
	}
	if _, err = io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("gostx509: PBES2 salt: %w", err)
	}
	if _, err = io.ReadFull(random, ukm); err != nil {
		return nil, fmt.Errorf("gostx509: PBES2 UKM: %w", err)
	}
	keyBytes, err := pbkdf2.Key(gost34112012512.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(keyBytes)
	var ciphertext []byte
	if legacy {
		stream, err := gost28147.NewMeshedCFBEncrypter(keyBytes, &gost28147.SboxIdtc26gost28147paramZ, ukm)
		if err != nil {
			return nil, err
		}
		ciphertext = make([]byte, len(plain))
		stream.XORKeyStream(ciphertext, plain)
	} else {
		ciphertext, err = cryptPBES2Authenticated(plain, keyBytes, ukm, magma, true)
		if err != nil {
			return nil, err
		}
	}
	prf := pkix.AlgorithmIdentifier{Algorithm: oidHMACStreebog512, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}
	kdfParams, err := asn1.Marshal(pbkdf2Parameters{Salt: salt, IterationCount: iterations, PRF: prf})
	if err != nil {
		return nil, err
	}
	var encParams []byte
	if legacy {
		encParams, err = asn1.Marshal(legacyPBES2CipherParameters{IV: ukm, EncryptionParamSet: oidPBES2TC26Z})
	} else {
		encParams, err = asn1.Marshal(gostPBES2CipherParameters{UKM: ukm})
	}
	if err != nil {
		return nil, err
	}
	pbesParams, err := asn1.Marshal(pbes2Parameters{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: encOID, Parameters: asn1.RawValue{FullBytes: encParams}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbesParams}},
		EncryptedData:       ciphertext,
	})
}

// ParseEncryptedPKCS8PrivateKey decrypts RFC 9337 PBES2. The OMAC variants
// authenticate the ciphertext; plain CTR-ACPKM variants do not and should
// only be used inside an independently authenticated container such as PFX.
func ParseEncryptedPKCS8PrivateKey(der []byte, password string) (any, error) {
	if len(der) > maxEncryptedPKCS8Size+4096 {
		return nil, errors.New("gostx509: encrypted PKCS #8 too large")
	}
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed encrypted PKCS #8")
	}
	plain, err := decryptPBES2(info.EncryptionAlgorithm, info.EncryptedData, password)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return ParsePKCS8PrivateKey(plain)
}

func decryptPBES2(algorithm pkix.AlgorithmIdentifier, ciphertext []byte, password string) ([]byte, error) {
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("gostx509: unsupported encrypted PKCS #8 algorithm")
	}
	var params pbes2Parameters
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed PBES2 parameters")
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("gostx509: unsupported PBES2 key derivation")
	}
	var kdf pbkdf2Parameters
	rest, err = asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf)
	if err != nil || len(rest) != 0 || len(kdf.Salt) < 8 || len(kdf.Salt) > 32 || kdf.IterationCount < 1000 || kdf.IterationCount > maxPKCS8Iterations || (kdf.KeyLength != 0 && kdf.KeyLength != 32) || !kdf.PRF.Algorithm.Equal(oidHMACStreebog512) || string(kdf.PRF.Parameters.FullBytes) != "\x05\x00" {
		return nil, errors.New("gostx509: unsupported PBKDF2 parameters")
	}
	magma := false
	authenticated := false
	switch {
	case params.EncryptionScheme.Algorithm.Equal(oidPBES2GOST28147):
		var enc legacyPBES2CipherParameters
		rest, err = asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &enc)
		if err != nil || len(rest) != 0 || len(enc.IV) != gost28147.BlockSize {
			return nil, errors.New("gostx509: malformed GOST 28147 PBES2 parameters")
		}
		var sbox *gost28147.Sbox
		switch {
		case enc.EncryptionParamSet.Equal(oidPBES2CryptoProA):
			sbox = &gost28147.SboxIdGost2814789CryptoProAParamSet
		case enc.EncryptionParamSet.Equal(oidPBES2CryptoProB):
			sbox = &gost28147.SboxIdGost2814789CryptoProBParamSet
		case enc.EncryptionParamSet.Equal(oidPBES2CryptoProC):
			sbox = &gost28147.SboxIdGost2814789CryptoProCParamSet
		case enc.EncryptionParamSet.Equal(oidPBES2CryptoProD):
			sbox = &gost28147.SboxIdGost2814789CryptoProDParamSet
		case enc.EncryptionParamSet.Equal(oidPBES2TC26Z):
			sbox = &gost28147.SboxIdtc26gost28147paramZ
		default:
			return nil, errors.New("gostx509: unsupported GOST 28147 PBES2 parameter set")
		}
		keyBytes, err := pbkdf2.Key(gost34112012512.New, password, kdf.Salt, kdf.IterationCount, 32)
		if err != nil {
			return nil, err
		}
		defer clear(keyBytes)
		stream, err := gost28147.NewMeshedCFBDecrypter(keyBytes, sbox, enc.IV)
		if err != nil {
			return nil, err
		}
		plain := make([]byte, len(ciphertext))
		stream.XORKeyStream(plain, ciphertext)
		return plain, nil
	case params.EncryptionScheme.Algorithm.Equal(oidKuznechikCTRACPKMOMAC):
		authenticated = true
	case params.EncryptionScheme.Algorithm.Equal(oidMagmaCTRACPKMOMAC):
		magma = true
		authenticated = true
	case params.EncryptionScheme.Algorithm.Equal(oidKuznechikCTRACPKM):
	case params.EncryptionScheme.Algorithm.Equal(oidMagmaCTRACPKM):
		magma = true
	default:
		return nil, errors.New("gostx509: unsupported PBES2 encryption scheme")
	}
	var enc gostPBES2CipherParameters
	rest, err = asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &enc)
	if err != nil || len(rest) != 0 || len(enc.UKM) != 16 && !magma || len(enc.UKM) != 12 && magma {
		return nil, errors.New("gostx509: malformed PBES2 UKM")
	}
	keyBytes, err := pbkdf2.Key(gost34112012512.New, password, kdf.Salt, kdf.IterationCount, 32)
	if err != nil {
		return nil, err
	}
	defer clear(keyBytes)
	if authenticated {
		return cryptPBES2Authenticated(ciphertext, keyBytes, enc.UKM, magma, false)
	}
	var stream *modes.CTRACPKM
	if magma {
		cipher, err := modes.NewMagma(keyBytes)
		if err != nil {
			return nil, err
		}
		stream, err = cipher.CTRACPKM(enc.UKM[:4], pkcs8SectionSize)
		if err != nil {
			return nil, err
		}
	} else {
		cipher, err := modes.NewKuznechik(keyBytes)
		if err != nil {
			return nil, err
		}
		stream, err = cipher.CTRACPKM(enc.UKM[:8], pkcs8SectionSize)
		if err != nil {
			return nil, err
		}
	}
	defer stream.Close()
	return stream.Decrypt(nil, ciphertext)
}

func cryptPBES2Authenticated(input, passwordKey, ukm []byte, magma, encrypt bool) ([]byte, error) {
	var subkeys [64]byte
	if err := gost34112012256.NewKDF(passwordKey).DeriveTreeInto(subkeys[:], []byte("kdf tree"), ukm[len(ukm)-8:], 1); err != nil {
		return nil, err
	}
	defer clear(subkeys[:])
	var stream *modes.CTRACPKM
	var mac *modes.MAC
	var err error
	if magma {
		cipher, e := modes.NewMagma(subkeys[:32])
		if e != nil {
			return nil, e
		}
		stream, err = cipher.CTRACPKM(ukm[:4], pkcs8SectionSize)
		if err != nil {
			return nil, err
		}
		macCipher, e := modes.NewMagma(subkeys[32:])
		if e != nil {
			return nil, e
		}
		mac, err = macCipher.MAC(8)
	} else {
		cipher, e := modes.NewKuznechik(subkeys[:32])
		if e != nil {
			return nil, e
		}
		stream, err = cipher.CTRACPKM(ukm[:8], pkcs8SectionSize)
		if err != nil {
			return nil, err
		}
		macCipher, e := modes.NewKuznechik(subkeys[32:])
		if e != nil {
			return nil, e
		}
		mac, err = macCipher.MAC(16)
	}
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if encrypt {
		body := append([]byte(nil), input...)
		body = mac.Sum(body, input)
		return stream.Encrypt(nil, body)
	}
	tagSize := 16
	if magma {
		tagSize = 8
	}
	if len(input) < tagSize {
		return nil, errors.New("gostx509: truncated encrypted PKCS #8")
	}
	plain, err := stream.Decrypt(nil, input)
	if err != nil {
		return nil, err
	}
	message := plain[:len(plain)-tagSize]
	if !mac.Verify(message, plain[len(message):]) {
		clear(plain)
		return nil, errors.New("gostx509: invalid encrypted PKCS #8 password or authentication tag")
	}
	return message, nil
}
