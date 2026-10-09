package gost34112012

import (
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	base64 "gitverse.ru/uzer_007/gobase64"
	"gitverse.ru/uzer_007/gogost/v3/internal/yescrypt"
)

// GostYescrypt256 = HMAC256 (HMAC256 (sb256(P),S), yescrypt(P,S))
const (
	gostYescryptPrefix          = "$gy$"
	gostYescryptParams256       = "Tj0zMjc2OCxyPTgscD0xLGtleUxlbj0zMg=="
	gostYescryptParams512       = "Tj0zMjc2OCxyPTgscD0xLGtleUxlbj02NA=="
	gostYescryptRecordPrefix256 = gostYescryptPrefix + gostYescryptParams256 + "$"
	gostYescryptRecordPrefix512 = gostYescryptPrefix + gostYescryptParams512 + "$"
	gostYescryptInlineSaltSize  = 32
	gostYescryptMaxHashSize     = 64
)

var (
	gostYescryptBase64             = base64.StdEncoding.Strict()
	errUnsupportedGostYescryptSize = errors.New("gogost/internal/gost34112012: Неподдерживаемый размер ключа")
	errInvalidGostYescryptHash     = errors.New("gogost/internal/gost34112012: некорректный формат GOST yescrypt-хеша")
)

// GostYescrypt вычисляет хеш по алгоритму GOSTR3411_2012 с yescrypt
func GostYescrypt(size uint16, salt []byte, password []byte) ([]byte, error) {
	keyLen := int(size / 8)
	if keyLen != 32 && keyLen != 64 {
		return nil, errUnsupportedGostYescryptSize
	}

	var passwordHash, innerHMAC [gostYescryptMaxHashSize]byte
	if keyLen == 32 {
		digest := Sum256(password)
		copy(passwordHash[:32], digest[:])
		clear(digest[:])
	} else {
		digest := Sum512(password)
		copy(passwordHash[:], digest[:])
		clear(digest[:])
	}

	gostHMACInto(innerHMAC[:keyLen], keyLen, salt, passwordHash[:keyLen])
	clear(passwordHash[:])

	yc, err := yescrypt.Key(password, salt, keyLen)
	if err != nil {
		clear(innerHMAC[:])
		return nil, err
	}

	result := make([]byte, keyLen)
	gostHMACInto(result, keyLen, yc, innerHMAC[:keyLen])
	clear(yc)
	clear(innerHMAC[:])
	return result, nil
}

// gostHMACInto computes HMAC-Streebog without converting Hash through the
// hash.Hash interface. All pads and intermediate digests stay in fixed-size
// local buffers.
func gostHMACInto(out []byte, size int, key, message []byte) {
	var pad [BlockSize]byte
	if len(key) <= BlockSize {
		copy(pad[:], key)
	} else if size == 32 {
		digest := Sum256(key)
		copy(pad[:32], digest[:])
		clear(digest[:])
	} else {
		digest := Sum512(key)
		copy(pad[:], digest[:])
		clear(digest[:])
	}

	for i := range pad {
		pad[i] ^= 0x36
	}
	inner := NewValue(size)
	_, _ = inner.Write(pad[:])
	_, _ = inner.Write(message)
	innerDigest := inner.checkSum()

	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	outer := NewValue(size)
	_, _ = outer.Write(pad[:])
	if size == 32 {
		_, _ = outer.Write(innerDigest[BlockSize/2:])
	} else {
		_, _ = outer.Write(innerDigest[:])
	}
	outerDigest := outer.checkSum()
	if size == 32 {
		copy(out, outerDigest[BlockSize/2:])
	} else {
		copy(out, outerDigest[:])
	}

	clear(pad[:])
	clear(innerDigest[:])
	clear(outerDigest[:])
}

func gostYescryptParams(size uint16) string {
	switch size {
	case 256:
		return gostYescryptParams256
	case 512:
		return gostYescryptParams512
	default:
		// Динамическая генерация для нестандартных размеров
		return gostYescryptBase64.EncodeToString(
			[]byte("N=32768,r=8,p=1,keyLen=" + strconv.Itoa(int(size/8))),
		)
	}
}

func FormatGostYescryptHash(size uint16, salt, hash []byte) string {
	var prefix string
	switch size {
	case 256:
		prefix = gostYescryptRecordPrefix256
	case 512:
		prefix = gostYescryptRecordPrefix512
	default:
		prefix = gostYescryptPrefix + gostYescryptParams(size) + "$"
	}

	saltB64Size := gostYescryptBase64.EncodedLen(len(salt))
	hashB64Size := gostYescryptBase64.EncodedLen(len(hash))
	encodedSize := len(prefix) + saltB64Size + hashB64Size + 1
	encoded := make([]byte, encodedSize)
	offset := copy(encoded, prefix)

	gostYescryptBase64.Encode(encoded[offset:offset+saltB64Size], salt)
	offset += saltB64Size
	encoded[offset] = '$'
	offset++
	gostYescryptBase64.Encode(encoded[offset:], hash)

	// encoded больше нигде не доступен, поэтому zero-copy преобразование безопасно.
	return unsafe.String(unsafe.SliceData(encoded), len(encoded))
}

// readOnlyStringBytes возвращает представление строки без аллокации.
// Полученный срез разрешено передавать только функциям, которые не меняют src.
func readOnlyStringBytes(value string) []byte {
	if value == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(value), len(value))
}

// VerifyGostYescryptHash проверяет пароль по канонической строке,
// сформированной FormatGostYescryptHash для указанного размера хеша.
func VerifyGostYescryptHash(size uint16, encoded string, password []byte) (bool, error) {
	var prefix string
	switch size {
	case 256:
		prefix = gostYescryptRecordPrefix256
	case 512:
		prefix = gostYescryptRecordPrefix512
	default:
		return false, errUnsupportedGostYescryptSize
	}

	rest, ok := strings.CutPrefix(encoded, prefix)
	if !ok {
		return false, errInvalidGostYescryptHash
	}

	saltB64, hashB64, ok := strings.Cut(rest, "$")
	if !ok || strings.ContainsRune(hashB64, '$') {
		return false, errInvalidGostYescryptHash
	}
	hashSize := int(size / 8)
	if len(hashB64) != gostYescryptBase64.EncodedLen(hashSize) {
		return false, errInvalidGostYescryptHash
	}

	var decoded [gostYescryptMaxHashSize + gostYescryptInlineSaltSize]byte
	expected := decoded[:hashSize]
	n, ok := gostYescryptBase64.FastDecode(expected, readOnlyStringBytes(hashB64))
	if !ok || n != hashSize {
		clear(decoded[:])
		return false, errInvalidGostYescryptHash
	}

	saltBufferSize := gostYescryptBase64.DecodedLen(len(saltB64))
	var saltBuffer []byte
	if saltBufferSize <= gostYescryptInlineSaltSize {
		saltBuffer = decoded[gostYescryptMaxHashSize : gostYescryptMaxHashSize+saltBufferSize]
	} else {
		saltBuffer = make([]byte, saltBufferSize)
	}

	n, ok = gostYescryptBase64.FastDecode(saltBuffer, readOnlyStringBytes(saltB64))
	if !ok {
		clear(saltBuffer)
		clear(decoded[:])
		return false, errInvalidGostYescryptHash
	}
	salt := saltBuffer[:n]

	actual, err := GostYescrypt(size, salt, password)
	if err != nil {
		clear(saltBuffer)
		clear(decoded[:])
		return false, err
	}

	match := subtle.ConstantTimeCompare(expected, actual) == 1
	clear(actual)
	clear(saltBuffer)
	clear(decoded[:])
	return match, nil
}
