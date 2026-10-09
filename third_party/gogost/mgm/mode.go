// Package mgm реализует режим аутентифицированного шифрования MGM для
// 64- и 128-битных блочных шифров ГОСТ.
package mgm

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"unsafe"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

var InvalidTag = errors.New("gogost/mgm: Некорректный тег аутентификации")

const authBatchBytes = 128

type bulkBlock interface {
	EncryptBlocks(dst, src []byte)
}

type compactBulkBlock interface {
	EncryptBlocksCompact(dst, src []byte)
}

type ctrBlock interface {
	XORKeyStreamCTRCounter(dst, src, counter []byte)
}

type MGM struct {
	cipher    cipher.Block
	bulk      bulkBlock
	compact   compactBulkBlock
	ctr       ctrBlock
	icn       [16]byte
	bufP      [16]byte
	bufC      [16]byte
	padded    [16]byte
	sum       [16]byte
	batch     [authBatchBytes]byte
	MaxSize   uint64
	BlockSize int
	TagSize   int
}

func NewMGM(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	blockSize := block.BlockSize()
	if !(blockSize == 8 || blockSize == 16) {
		return nil, errors.New("gogost/mgm: допустимы только размеры блока 64 или 128 бит")
	}
	if tagSize < 4 || tagSize > blockSize {
		return nil, errors.New("gogost/mgm: Некорректный размер тега (4<=" + errx.Int(tagSize) + "<=" + errx.Int(blockSize) + ")")
	}
	mgm := MGM{
		MaxSize:   uint64(1<<uint(blockSize*8/2) - 1),
		BlockSize: blockSize,
		TagSize:   tagSize,
		cipher:    block,
	}
	// Magma's regular multi-block backend is compact. Kuznyechik deliberately
	// uses its smaller-table backend here: the faster pair-LUT ECB backend
	// evicts MGM's authentication state and regresses the complete operation.
	if blockSize == 8 {
		mgm.bulk, _ = block.(bulkBlock)
	} else {
		mgm.compact, _ = block.(compactBulkBlock)
	}
	mgm.ctr, _ = block.(ctrBlock)
	return &mgm, nil
}

func (mgm *MGM) NonceSize() int {
	return mgm.BlockSize
}

func (mgm *MGM) Overhead() int {
	return mgm.TagSize
}

func incr(data []byte) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i]++
		if data[i] != 0 {
			return
		}
	}
}

func (mgm *MGM) validateNonce(nonce []byte) {
	if len(nonce) != mgm.BlockSize {
		panic("gogost/mgm: длина nonce должна быть равна размеру блока шифра")
	}
	if nonce[0]&0x80 > 0 {
		panic("gogost/mgm: старший бит nonce должен быть нулём")
	}
}

func (mgm *MGM) validateSizes(text, additionalData []byte) {
	if len(text) == 0 && len(additionalData) == 0 {
		panic("gogost/mgm: требуется текст или дополнительные данные")
	}
	if uint64(len(additionalData)) > mgm.MaxSize {
		panic("gogost/mgm: дополнительные данные слишком большие")
	}
	if uint64(len(text)+len(additionalData)) > mgm.MaxSize {
		panic("gogost/mgm: текст вместе с дополнительными данными слишком большой")
	}
}

func (mgm *MGM) auth(out, text, ad []byte) {
	bs := mgm.BlockSize
	clear(mgm.sum[:])
	adLen := len(ad) * 8
	textLen := len(text) * 8
	mgm.icn[0] |= 0x80
	mgm.cipher.Encrypt(mgm.bufP[:bs], mgm.icn[:bs]) // Z_1 = E_K(1 || ICN)
	ad = mgm.authFullBlocks(ad)
	if len(ad) > 0 {
		copy(mgm.padded[:bs], ad)
		clear(mgm.padded[len(ad):bs])
		mgm.cipher.Encrypt(mgm.bufC[:bs], mgm.bufP[:bs])
		mgm.mulAdd(mgm.bufC[:bs], mgm.padded[:bs])
		incr(mgm.bufP[:mgm.BlockSize/2])
	}

	text = mgm.authFullBlocks(text)
	if len(text) > 0 {
		copy(mgm.padded[:bs], text)
		for i := len(text); i < mgm.BlockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC[:bs], mgm.bufP[:bs])
		mgm.mulAdd(mgm.bufC[:bs], mgm.padded[:bs])
		incr(mgm.bufP[:mgm.BlockSize/2])
	}

	mgm.cipher.Encrypt(mgm.bufP[:bs], mgm.bufP[:bs]) // H_{h+q+1} = E_K(Z_{h+q+1})
	// len(A) || len(C)
	if mgm.BlockSize == 8 {
		binary.BigEndian.PutUint32(mgm.bufC[:], uint32(adLen))
		binary.BigEndian.PutUint32(mgm.bufC[mgm.BlockSize/2:], uint32(textLen))
	} else {
		binary.BigEndian.PutUint64(mgm.bufC[:], uint64(adLen))
		binary.BigEndian.PutUint64(mgm.bufC[mgm.BlockSize/2:], uint64(textLen))
	}
	// sum (xor)= H_{h+q+1} (x) (len(A) || len(C))
	mgm.mulAdd(mgm.bufC[:bs], mgm.bufP[:bs])
	mgm.cipher.Encrypt(mgm.bufP[:bs], mgm.sum[:bs]) // E_K(sum)
	copy(out, mgm.bufP[:mgm.TagSize])               // MSB_S(E_K(sum))
}

func (mgm *MGM) authFullBlocks(data []byte) []byte {
	bs := mgm.BlockSize
	if mgm.bulk != nil || mgm.compact != nil {
		batchBlocks := len(mgm.batch) / bs
		for len(data) >= 8*bs {
			blocks := len(data) / bs
			if blocks > batchBlocks {
				blocks = batchBlocks
			}
			n := blocks * bs
			hashes := mgm.batch[:n]
			for i := range blocks {
				off := i * bs
				copy(hashes[off:off+bs], mgm.bufP[:bs])
				incr(mgm.bufP[:bs/2])
			}
			if mgm.compact != nil {
				mgm.compact.EncryptBlocksCompact(hashes, hashes)
			} else {
				mgm.bulk.EncryptBlocks(hashes, hashes)
			}
			for i := range blocks {
				off := i * bs
				mgm.mulAdd(hashes[off:off+bs], data[off:off+bs])
			}
			data = data[n:]
		}
	}
	for len(data) >= bs {
		mgm.cipher.Encrypt(mgm.bufC[:bs], mgm.bufP[:bs])
		mgm.mulAdd(mgm.bufC[:bs], data[:bs])
		incr(mgm.bufP[:bs/2])
		data = data[bs:]
	}
	return data
}

func (mgm *MGM) mulAdd(h, block []byte) {
	if mgm.BlockSize == 8 {
		mulAdd64(mgm.sum[:8], h, block)
		return
	}
	mulAdd128(mgm.sum[:16], h, block)
}

/*
	func (mgm *MGM) crypt(out, in []byte) {
		mgm.icn[0] &= 0x7F
		mgm.cipher.Encrypt(mgm.bufP, mgm.icn) // Y_1 = E_K(0 || ICN)
		for len(in) >= mgm.BlockSize {
			mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // E_K(Y_i)
			subtle.XORBytes(out, mgm.bufC, in)     // C_i = P_i (xor) E_K(Y_i)
			incr(mgm.bufP[mgm.BlockSize/2:])       // Y_i = incr_r(Y_{i-1})
			out = out[mgm.BlockSize:]
			in = in[mgm.BlockSize:]
		}
		if len(in) > 0 {
			mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
			for i := 0; i < len(in); i++ {
				out[i] = in[i] ^ mgm.bufC[i]
			}
		}
	}
*/
func (mgm *MGM) crypt(out, in []byte) {
	mgm.icn[0] &= 0x7F
	mgm.cipher.Encrypt(mgm.bufP[:mgm.BlockSize], mgm.icn[:mgm.BlockSize]) // Y_1 = E_K(0 || ICN)
	if len(in) == 0 {
		return
	}
	if mgm.ctr != nil && !inexactOverlap(out, in) {
		mgm.ctr.XORKeyStreamCTRCounter(out, in, mgm.bufP[:mgm.BlockSize])
		return
	}

	bs := mgm.BlockSize
	var tmp [16]byte // MGM поддерживает только 8 или 16

	for len(in) >= bs {
		mgm.cipher.Encrypt(mgm.bufC[:bs], mgm.bufP[:bs]) // E_K(Y_i)

		// Копируем входной блок, чтобы XOR был безопасен при любом overlap(out,in)
		copy(tmp[:bs], in[:bs])
		for i := 0; i < bs; i++ {
			out[i] = tmp[i] ^ mgm.bufC[i]
		}

		incr(mgm.bufP[bs/2 : bs]) // Y_i = incr_r(Y_{i-1})
		out = out[bs:]
		in = in[bs:]
	}

	if len(in) > 0 {
		mgm.cipher.Encrypt(mgm.bufC[:bs], mgm.bufP[:bs])
		copy(tmp[:len(in)], in)
		for i := 0; i < len(in); i++ {
			out[i] = tmp[i] ^ mgm.bufC[i]
		}
	}
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	x0 := uintptr(unsafe.Pointer(&x[0]))
	y0 := uintptr(unsafe.Pointer(&y[0]))
	return x0 <= y0+uintptr(len(y))-1 && y0 <= x0+uintptr(len(x))-1
}

func (mgm *MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	mgm.validateNonce(nonce)
	mgm.validateSizes(plaintext, additionalData)
	if uint64(len(plaintext)) > mgm.MaxSize {
		panic("gogost/mgm: plaintext слишком большой")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+mgm.TagSize)
	copy(mgm.icn[:mgm.BlockSize], nonce)
	mgm.crypt(out, plaintext)
	mgm.auth(
		out[len(plaintext):len(plaintext)+mgm.TagSize],
		out[:len(plaintext)],
		additionalData,
	)
	return ret
}

// Open проверяет и расшифровывает аутентифицированный ciphertext.
// При неверном теге возвращается InvalidTag.
func (mgm *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	mgm.validateNonce(nonce)
	mgm.validateSizes(ciphertext, additionalData)
	if len(ciphertext) < mgm.TagSize {
		return nil, errors.New("gogost/mgm: ciphertext слишком короткий (" + errx.Int(len(ciphertext)) + "<" + errx.Int(mgm.TagSize) + ")")
	}
	if uint64(len(ciphertext)-mgm.TagSize) > mgm.MaxSize {
		panic("gogost/mgm: ciphertext слишком большой")
	}
	ret, out := sliceForAppend(dst, len(ciphertext)-mgm.TagSize)
	ct := ciphertext[:len(ciphertext)-mgm.TagSize]
	copy(mgm.icn[:mgm.BlockSize], nonce)
	mgm.auth(mgm.sum[:mgm.BlockSize], ct, additionalData)
	if !hmac.Equal(mgm.sum[:mgm.TagSize], ciphertext[len(ciphertext)-mgm.TagSize:]) {
		return nil, InvalidTag
	}
	mgm.crypt(out, ct)
	return ret, nil
}
