// Package gost3412128 реализует 128-битный блочный шифр Кузнечик
// (ГОСТ Р 34.12-2015) с оптимизированным fast path.
package gost3412128

const (
	BlockSize = 16
	KeySize   = 32
)

func xorBlockInPlace(dst, src *[BlockSize]byte) {
	dst[0] ^= src[0]
	dst[1] ^= src[1]
	dst[2] ^= src[2]
	dst[3] ^= src[3]
	dst[4] ^= src[4]
	dst[5] ^= src[5]
	dst[6] ^= src[6]
	dst[7] ^= src[7]
	dst[8] ^= src[8]
	dst[9] ^= src[9]
	dst[10] ^= src[10]
	dst[11] ^= src[11]
	dst[12] ^= src[12]
	dst[13] ^= src[13]
	dst[14] ^= src[14]
	dst[15] ^= src[15]
}

var (
	// cBlk - массив блоков для констант.
	cBlk [32]*[BlockSize]byte

	// gfCache - кэш для ускорения вычислений в поле Галуа.
	gfCache [256][256]byte
)

// Линейное преобразование L для блока данных.
func l(blk *[BlockSize]byte) {
	for range BlockSize {
		blk[0],
			blk[1],
			blk[2],
			blk[3],
			blk[4],
			blk[5],
			blk[6],
			blk[7],
			blk[8],
			blk[9],
			blk[10],
			blk[11],
			blk[12],
			blk[13],
			blk[14],
			blk[15] = (blk[15] ^
			gfCache[blk[0]][lVector[0]] ^
			gfCache[blk[1]][lVector[1]] ^
			gfCache[blk[2]][lVector[2]] ^
			gfCache[blk[3]][lVector[3]] ^
			gfCache[blk[4]][lVector[4]] ^
			gfCache[blk[5]][lVector[5]] ^
			gfCache[blk[6]][lVector[6]] ^
			gfCache[blk[7]][lVector[7]] ^
			gfCache[blk[8]][lVector[8]] ^
			gfCache[blk[9]][lVector[9]] ^
			gfCache[blk[10]][lVector[10]] ^
			gfCache[blk[11]][lVector[11]] ^
			gfCache[blk[12]][lVector[12]] ^
			gfCache[blk[13]][lVector[13]] ^
			gfCache[blk[14]][lVector[14]]),
			blk[0],
			blk[1],
			blk[2],
			blk[3],
			blk[4],
			blk[5],
			blk[6],
			blk[7],
			blk[8],
			blk[9],
			blk[10],
			blk[11],
			blk[12],
			blk[13],
			blk[14]
	}
}

// Обратное линейное преобразование L^-1 для блока данных.
func lInv(blk *[BlockSize]byte) {
	var t byte
	for range BlockSize {
		t = blk[0]
		copy(blk[:], blk[1:])
		t ^= gfCache[blk[0]][lVector[0]]
		t ^= gfCache[blk[1]][lVector[1]]
		t ^= gfCache[blk[2]][lVector[2]]
		t ^= gfCache[blk[3]][lVector[3]]
		t ^= gfCache[blk[4]][lVector[4]]
		t ^= gfCache[blk[5]][lVector[5]]
		t ^= gfCache[blk[6]][lVector[6]]
		t ^= gfCache[blk[7]][lVector[7]]
		t ^= gfCache[blk[8]][lVector[8]]
		t ^= gfCache[blk[9]][lVector[9]]
		t ^= gfCache[blk[10]][lVector[10]]
		t ^= gfCache[blk[11]][lVector[11]]
		t ^= gfCache[blk[12]][lVector[12]]
		t ^= gfCache[blk[13]][lVector[13]]
		t ^= gfCache[blk[14]][lVector[14]]
		blk[15] = t
	}
}

// Нелинейное преобразование S для блока данных.
func s(blk *[BlockSize]byte) {
	blk[0] = piTable[int(blk[0])]
	blk[1] = piTable[int(blk[1])]
	blk[2] = piTable[int(blk[2])]
	blk[3] = piTable[int(blk[3])]
	blk[4] = piTable[int(blk[4])]
	blk[5] = piTable[int(blk[5])]
	blk[6] = piTable[int(blk[6])]
	blk[7] = piTable[int(blk[7])]
	blk[8] = piTable[int(blk[8])]
	blk[9] = piTable[int(blk[9])]
	blk[10] = piTable[int(blk[10])]
	blk[11] = piTable[int(blk[11])]
	blk[12] = piTable[int(blk[12])]
	blk[13] = piTable[int(blk[13])]
	blk[14] = piTable[int(blk[14])]
	blk[15] = piTable[int(blk[15])]
}

func sInv(blk *[BlockSize]byte) {
	for n := range BlockSize {
		blk[n] = piInverseTable[int(blk[n])]
	}
}

// init инициализирует вспомогательные структуры данных.
func init() {
	// Заполняем кэш для умножения в поле Галуа
	for a := range 256 {
		for b := range 256 {
			gfCache[a][b] = gf2Mul(byte(a), byte(b))
		}
	}
	// Инициализируем массив cBlk для использования в генерации раундовых ключей.
	for i := range 32 {
		cBlk[i] = new([BlockSize]byte)
		cBlk[i][15] = byte(i) + 1
		l(cBlk[i])
	}
}

// Cipher представляет шифр с раундовыми ключами.
type Cipher struct {
	ks    [10][BlockSize]byte
	decKs [10][BlockSize]byte
	macK1 [BlockSize]byte
	macK2 [BlockSize]byte
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

// NewCipher создает новый экземпляр шифра с заданным ключом.
func NewCipher(key []byte) *Cipher {
	c := new(Cipher)
	c.SetKey(key)
	return c
}

// SetKey replaces the cipher key and refreshes every derived round and MAC
// subkey. It is intended for protocol constructions such as TLS TLSTREE that
// rekey an otherwise unchanged cipher instance. SetKey must not run
// concurrently with other Cipher methods.
func (c *Cipher) SetKey(key []byte) {
	if len(key) != KeySize {
		panic(keySizeError(len(key)))
	}

	initCipherTables()

	var raw [KeySize]byte
	copy(raw[:], key)
	ks := stretchKey(raw)

	c.ks = ks
	c.decKs = decryptRoundKeys(ks)
	c.initMACSubkeys()
}

// Encrypt шифрует один блок данных.
func (c *Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("gogost/gost3412128: вход не является полным блоком")
	}
	if len(dst) < BlockSize {
		panic("gogost/gost3412128: выходной буфер не является полным блоком")
	}

	encryptBlock(
		(*[BlockSize]byte)(dst[:BlockSize]),
		(*[BlockSize]byte)(src[:BlockSize]),
		&c.ks,
	)
}

// Decrypt расшифровывает один блок данных.
func (c *Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("gogost/gost3412128: вход не является полным блоком")
	}
	if len(dst) < BlockSize {
		panic("gogost/gost3412128: выходной буфер не является полным блоком")
	}

	decryptBlock(
		(*[BlockSize]byte)(dst[:BlockSize]),
		(*[BlockSize]byte)(src[:BlockSize]),
		&c.decKs,
	)
}
