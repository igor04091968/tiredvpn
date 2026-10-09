//go:build amd64 && !purego
// +build amd64,!purego

package gost3412128

import "sync"

var (
	lsEncPairLookup     [8][1 << 16][16]byte
	lInvPairLookup      [8][1 << 16][16]byte
	slDecPairLookup     [8][1 << 16][16]byte
	piInvPairLookup     [8][1 << 16][16]byte
	lsEncPairLookupOnce sync.Once
	decPairLookupOnce   sync.Once
)

// ensureEncryptPairLookup строит глобальную таблицу пар байтов для bulk
// шифрования. Таблица общая для всех ключей и не увеличивает размер Cipher.
func ensureEncryptPairLookup() {
	initCipherTables()
	lsEncPairLookupOnce.Do(func() {
		buildPairLookup(&lsEncPairLookup, &lsEncLookup)
	})
}

// ensureDecryptPairLookup строит глобальные таблицы пар байтов для bulk
// расшифровки. Они ленивые и не влияют на задержку одиночного блока.
func ensureDecryptPairLookup() {
	initCipherTables()
	decPairLookupOnce.Do(func() {
		buildPairLookup(&lInvPairLookup, &lInvLookup)
		buildPairLookup(&slDecPairLookup, &slDecLookup)
		for pair := 0; pair < 8; pair++ {
			pos := pair * 2
			for v := 0; v < 1<<16; v++ {
				out := &piInvPairLookup[pair][v]
				out[pos] = piInverseTable[byte(v)]
				out[pos+1] = piInverseTable[byte(v>>8)]
			}
		}
	})
}

func buildPairLookup(dst *[8][1 << 16][16]byte, src *[16][256][16]byte) {
	for pair := 0; pair < 8; pair++ {
		first := &src[pair*2]
		second := &src[pair*2+1]
		for v := 0; v < 1<<16; v++ {
			a := &first[byte(v)]
			b := &second[byte(v>>8)]
			out := &dst[pair][v]
			out[0] = a[0] ^ b[0]
			out[1] = a[1] ^ b[1]
			out[2] = a[2] ^ b[2]
			out[3] = a[3] ^ b[3]
			out[4] = a[4] ^ b[4]
			out[5] = a[5] ^ b[5]
			out[6] = a[6] ^ b[6]
			out[7] = a[7] ^ b[7]
			out[8] = a[8] ^ b[8]
			out[9] = a[9] ^ b[9]
			out[10] = a[10] ^ b[10]
			out[11] = a[11] ^ b[11]
			out[12] = a[12] ^ b[12]
			out[13] = a[13] ^ b[13]
			out[14] = a[14] ^ b[14]
			out[15] = a[15] ^ b[15]
		}
	}
}
