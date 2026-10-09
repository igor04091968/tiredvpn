// Package gost28147 реализует блочный шифр ГОСТ 28147-89 и практические
// режимы работы ECB, CFB, CTR, MAC, а также обёртку ключей по RFC 4357.
package gost28147

const (
	BlockSize = 8
	KeySize   = 32
)

// Все операции 28147 выполняются с двумя 32-разрядными частями целого блока. nv - это представление этой части.
type nv uint32

// Циклический сдвиг на 11 бит.
func (n nv) shift11() nv {
	//return ((n << 11) & (1<<32 - 1)) | ((n >> (32 - 11)) & (1<<32 - 1))
	return n<<11 | n>>(32-11)
}

// Seq содержит номера итераций, используемые в самой функции шифрования.
// Например, процесс шифрования и дешифрования 28147 отличается только этой последовательностью.
type Seq []uint8

var (
	SeqEncrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
	})

	SeqDecrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
)

type Cipher struct {
	baseKeys       [8]nv
	encKeys        [32]nv
	decKeys        [32]nv
	macKeys        [16]nv
	table          *[4][256]nv
	t16            *t16Table
	custom         *[4][256]nv
	gost3413MacK1  [BlockSize]byte
	gost3413MacK2  [BlockSize]byte
	gost3413MacK1u uint64
	gost3413MacK2u uint64
	simdSbox       [8][32]byte
}

func NewCipher(key []byte, sbox *Sbox) *Cipher {
	c := NewCipherValue(key, sbox)
	return &c
}

func NewCipherValue(key []byte, sbox *Sbox) Cipher {
	var c Cipher
	c.SetKey(key, sbox)
	return c
}

func (c *Cipher) SetKey(key []byte, sbox *Sbox) {
	if len(key) != KeySize {
		panic("gogost/gost28147: Некорректный размер ключа")
	}

	x := [8]nv{
		nv(load32LE(key[0:4])),
		nv(load32LE(key[4:8])),
		nv(load32LE(key[8:12])),
		nv(load32LE(key[12:16])),
		nv(load32LE(key[16:20])),
		nv(load32LE(key[20:24])),
		nv(load32LE(key[24:28])),
		nv(load32LE(key[28:32])),
	}
	c.initTables(sbox)
	c.initRoundKeys(&x)
	c.initGOST3413MACSubkeys()
}

func makeSboxTable(sbox *Sbox) [4][256]nv {
	var table [4][256]nv
	for pos := range 4 {
		lo := sbox[pos*2]
		hi := sbox[pos*2+1]
		shift := uint(pos * 8)
		for b := range 256 {
			v := nv(lo[b&0x0f])<<shift | nv(hi[b>>4])<<(shift+4)
			table[pos][b] = v.shift11()
		}
	}
	return table
}

func makeSIMDSbox(sbox *Sbox) [8][32]byte {
	var table [8][32]byte
	for pos := range 8 {
		for i := range 16 {
			table[pos][i] = sbox[pos][i]
			table[pos][i+16] = sbox[pos][i]
		}
	}
	return table
}

var (
	sboxTableTest       = makeSboxTable(&SboxIdGost2814789TestParamSet)
	sboxTableCryptoProA = makeSboxTable(&SboxIdGost2814789CryptoProAParamSet)
	sboxTableCryptoProB = makeSboxTable(&SboxIdGost2814789CryptoProBParamSet)
	sboxTableCryptoProC = makeSboxTable(&SboxIdGost2814789CryptoProCParamSet)
	sboxTableCryptoProD = makeSboxTable(&SboxIdGost2814789CryptoProDParamSet)
	sboxTableTC26Z      = makeSboxTable(&SboxIdtc26gost28147paramZ)
	sboxTableR341194T   = makeSboxTable(&SboxIdGostR341194TestParamSet)
	sboxTableR341194CP  = makeSboxTable(&SboxIdGostR341194CryptoProParamSet)
	sboxTableEAC        = makeSboxTable(&SboxEACParamSet)
)

func knownSboxTable(sbox *Sbox) *[4][256]nv {
	switch sbox {
	case &SboxIdGost2814789TestParamSet:
		return &sboxTableTest
	case &SboxIdGost2814789CryptoProAParamSet:
		return &sboxTableCryptoProA
	case &SboxIdGost2814789CryptoProBParamSet:
		return &sboxTableCryptoProB
	case &SboxIdGost2814789CryptoProCParamSet:
		return &sboxTableCryptoProC
	case &SboxIdGost2814789CryptoProDParamSet:
		return &sboxTableCryptoProD
	case &SboxIdtc26gost28147paramZ:
		return &sboxTableTC26Z
	case &SboxIdGostR341194TestParamSet:
		return &sboxTableR341194T
	case &SboxIdGostR341194CryptoProParamSet:
		return &sboxTableR341194CP
	case &SboxEACParamSet:
		return &sboxTableEAC
	default:
		return nil
	}
}

func (c *Cipher) initTables(sbox *Sbox) {
	c.simdSbox = makeSIMDSbox(sbox)
	if table := knownSboxTable(sbox); table != nil {
		c.table = table
		c.t16 = knownSboxT16(sbox)
		c.custom = nil
		return
	}
	table := makeSboxTable(sbox)
	c.custom = &table
	c.table = c.custom
	c.t16 = nil
}

func (c *Cipher) initRoundKeys(x *[8]nv) {
	c.baseKeys = *x
	for i, idx := range SeqEncrypt {
		c.encKeys[i] = x[idx]
	}
	for i, idx := range SeqDecrypt {
		c.decKeys[i] = x[idx]
	}
	for i, idx := range SeqMAC {
		c.macKeys[i] = x[idx]
	}
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

// Преобразование двоичного байтового блока в два внутренних целых числа по 32 бита.
func block2nvs(b []byte) (n1, n2 nv) {
	n1 = nv(load32LE(b[0:4]))
	n2 = nv(load32LE(b[4:8]))
	return
}

// Преобразование двух внутренних целых чисел по 32 бита в двоичный байтовый блок.
func nvs2block(n1, n2 nv, b []byte) {
	store32LE(b[0:4], uint32(n2))
	store32LE(b[4:8], uint32(n1))
}

func sboxLookup(table *[4][256]nv, n nv) nv {
	return table[0][byte(n)] ^
		table[1][byte(n>>8)] ^
		table[2][byte(n>>16)] ^
		table[3][byte(n>>24)]
}

func sboxLookupRows(t0, t1, t2, t3 *[256]nv, n nv) nv {
	return t0[byte(n)] ^
		t1[byte(n>>8)] ^
		t2[byte(n>>16)] ^
		t3[byte(n>>24)]
}

// xcrypt32x4EncryptRows — encrypt-only bulk core для четырёх независимых
// блоков. 32 раунда намеренно развёрнуты, чтобы убрать цикл по раундовым ключам
// из EncryptBlocks и сохранить single-block path компактным.
func xcrypt32x4EncryptRows(
	keys *[8]nv,
	t0, t1, t2, t3 *[256]nv,
	a1, a2, b1, b2, c1, c2, d1, d2 nv,
) (nv, nv, nv, nv, nv, nv, nv, nv) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k0)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k0)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k0)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k0)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k1)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k1)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k1)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k1)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k2)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k2)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k2)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k2)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k3)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k3)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k3)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k3)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k4)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k4)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k4)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k4)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k5)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k5)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k5)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k5)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k6)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k6)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k6)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k6)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k7)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k7)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k7)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k7)^d2, d1

	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k0)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k0)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k0)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k0)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k1)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k1)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k1)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k1)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k2)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k2)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k2)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k2)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k3)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k3)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k3)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k3)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k4)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k4)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k4)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k4)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k5)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k5)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k5)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k5)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k6)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k6)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k6)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k6)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k7)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k7)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k7)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k7)^d2, d1

	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k0)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k0)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k0)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k0)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k1)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k1)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k1)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k1)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k2)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k2)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k2)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k2)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k3)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k3)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k3)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k3)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k4)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k4)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k4)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k4)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k5)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k5)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k5)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k5)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k6)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k6)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k6)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k6)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k7)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k7)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k7)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k7)^d2, d1

	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k7)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k7)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k7)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k7)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k6)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k6)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k6)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k6)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k5)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k5)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k5)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k5)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k4)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k4)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k4)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k4)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k3)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k3)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k3)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k3)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k2)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k2)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k2)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k2)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k1)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k1)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k1)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k1)^d2, d1
	a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k0)^a2, a1
	b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k0)^b2, b1
	c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k0)^c2, c1
	d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k0)^d2, d1
	return a1, a2, b1, b2, c1, c2, d1, d2
}

func xcrypt16(keys *[16]nv, table *[4][256]nv, n1, n2 nv) (nv, nv) {
	n1, n2 = sboxLookup(table, n1+keys[0])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[1])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[2])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[3])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[4])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[5])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[6])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[7])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[8])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[9])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[10])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[11])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[12])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[13])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[14])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[15])^n2, n1
	return n1, n2
}

func xcrypt32(keys *[32]nv, table *[4][256]nv, n1, n2 nv) (nv, nv) {
	n1, n2 = sboxLookup(table, n1+keys[0])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[1])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[2])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[3])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[4])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[5])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[6])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[7])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[8])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[9])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[10])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[11])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[12])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[13])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[14])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[15])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[16])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[17])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[18])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[19])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[20])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[21])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[22])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[23])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[24])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[25])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[26])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[27])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[28])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[29])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[30])^n2, n1
	n1, n2 = sboxLookup(table, n1+keys[31])^n2, n1
	return n1, n2
}

func xcrypt32Encrypt(keys *[8]nv, table *[4][256]nv, n1, n2 nv) (nv, nv) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k7)^n2, n1

	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k7)^n2, n1

	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k7)^n2, n1

	n1, n2 = sboxLookup(table, n1+k7)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	return n1, n2
}

func xcrypt32Decrypt(keys *[8]nv, table *[4][256]nv, n1, n2 nv) (nv, nv) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k7)^n2, n1

	n1, n2 = sboxLookup(table, n1+k7)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k0)^n2, n1

	n1, n2 = sboxLookup(table, n1+k7)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k0)^n2, n1

	n1, n2 = sboxLookup(table, n1+k7)^n2, n1
	n1, n2 = sboxLookup(table, n1+k6)^n2, n1
	n1, n2 = sboxLookup(table, n1+k5)^n2, n1
	n1, n2 = sboxLookup(table, n1+k4)^n2, n1
	n1, n2 = sboxLookup(table, n1+k3)^n2, n1
	n1, n2 = sboxLookup(table, n1+k2)^n2, n1
	n1, n2 = sboxLookup(table, n1+k1)^n2, n1
	n1, n2 = sboxLookup(table, n1+k0)^n2, n1
	return n1, n2
}

// Шифрование одного блока.
// Если предоставленные срезы короче размера блока, возникнет паника.
func (c *Cipher) Encrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	if t16 := c.t16; t16 != nil {
		n1, n2 = xcrypt32EncryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n1, n2 = xcrypt32Encrypt(&c.baseKeys, c.table, n1, n2)
	}
	nvs2block(n1, n2, dst)
}

// Дешифрование одного блока.
// Если предоставленные срезы короче размера блока, возникнет паника.
func (c *Cipher) Decrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	if t16 := c.t16; t16 != nil {
		n1, n2 = xcrypt32DecryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n1, n2 = xcrypt32Decrypt(&c.baseKeys, c.table, n1, n2)
	}
	nvs2block(n1, n2, dst)
}

func (c *Cipher) EncryptBlocks(dst, src []byte) {
	if len(src) == BlockSize {
		if len(dst) < len(src) {
			panic("gogost/gost28147: dst слишком короткий")
		}
		c.Encrypt(dst, src)
		return
	}
	c.encryptBlocks(dst, src)
}

func (c *Cipher) DecryptBlocks(dst, src []byte) {
	if len(src) == BlockSize {
		if len(dst) < len(src) {
			panic("gogost/gost28147: dst слишком короткий")
		}
		c.Decrypt(dst, src)
		return
	}
	c.cryptBlocks(dst, src, &c.decKeys)
}

func (c *Cipher) cryptBlocks(dst, src []byte, keys *[32]nv) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost28147: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost28147: dst слишком короткий")
	}
	if n := decryptBlocksSIMD(dst, src, keys, &c.simdSbox); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	if t16 := c.t16; t16 != nil {
		for len(src) >= 4*BlockSize {
			a1, a2 := block2nvs(src[0:8])
			b1, b2 := block2nvs(src[8:16])
			c1, c2 := block2nvs(src[16:24])
			d1, d2 := block2nvs(src[24:32])
			a1, a2, b1, b2, c1, c2, d1, d2 = xcrypt32x4T16(keys, t16, a1, a2, b1, b2, c1, c2, d1, d2)
			nvs2block(a1, a2, dst[0:8])
			nvs2block(b1, b2, dst[8:16])
			nvs2block(c1, c2, dst[16:24])
			nvs2block(d1, d2, dst[24:32])
			dst = dst[4*BlockSize:]
			src = src[4*BlockSize:]
		}
		for len(src) >= 2*BlockSize {
			a1, a2 := block2nvs(src[0:8])
			b1, b2 := block2nvs(src[8:16])
			a1, a2, b1, b2 = xcrypt32x2T16(keys, t16, a1, a2, b1, b2)
			nvs2block(a1, a2, dst[0:8])
			nvs2block(b1, b2, dst[8:16])
			dst = dst[2*BlockSize:]
			src = src[2*BlockSize:]
		}
		for len(src) >= BlockSize {
			n1, n2 := block2nvs(src)
			n1, n2 = xcrypt32T16(keys, t16, n1, n2)
			nvs2block(n1, n2, dst)
			dst = dst[BlockSize:]
			src = src[BlockSize:]
		}
		return
	}
	table := c.table
	t0, t1, t2, t3 := &table[0], &table[1], &table[2], &table[3]
	for len(src) >= 4*BlockSize {
		a1, a2 := block2nvs(src[0:8])
		b1, b2 := block2nvs(src[8:16])
		c1, c2 := block2nvs(src[16:24])
		d1, d2 := block2nvs(src[24:32])
		for i := 0; i < 32; i++ {
			k := keys[i]
			a1, a2 = sboxLookupRows(t0, t1, t2, t3, a1+k)^a2, a1
			b1, b2 = sboxLookupRows(t0, t1, t2, t3, b1+k)^b2, b1
			c1, c2 = sboxLookupRows(t0, t1, t2, t3, c1+k)^c2, c1
			d1, d2 = sboxLookupRows(t0, t1, t2, t3, d1+k)^d2, d1
		}
		nvs2block(a1, a2, dst[0:8])
		nvs2block(b1, b2, dst[8:16])
		nvs2block(c1, c2, dst[16:24])
		nvs2block(d1, d2, dst[24:32])
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= 2*BlockSize {
		a1, a2 := block2nvs(src[0:8])
		b1, b2 := block2nvs(src[8:16])
		a1, a2, b1, b2 = xcrypt32x2(keys, table, a1, a2, b1, b2)
		nvs2block(a1, a2, dst[0:8])
		nvs2block(b1, b2, dst[8:16])
		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}
	for len(src) >= BlockSize {
		n1, n2 := block2nvs(src)
		n1, n2 = xcrypt32(keys, table, n1, n2)
		nvs2block(n1, n2, dst)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

func (c *Cipher) encryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost28147: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost28147: dst слишком короткий")
	}
	if n := encryptBlocksSIMD(dst, src, &c.encKeys, &c.simdSbox); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	if t16 := c.t16; t16 != nil {
		for len(src) >= 4*BlockSize {
			a1, a2 := block2nvs(src[0:8])
			b1, b2 := block2nvs(src[8:16])
			c1, c2 := block2nvs(src[16:24])
			d1, d2 := block2nvs(src[24:32])
			a1, a2, b1, b2, c1, c2, d1, d2 = xcrypt32x4T16(&c.encKeys, t16, a1, a2, b1, b2, c1, c2, d1, d2)
			nvs2block(a1, a2, dst[0:8])
			nvs2block(b1, b2, dst[8:16])
			nvs2block(c1, c2, dst[16:24])
			nvs2block(d1, d2, dst[24:32])
			dst = dst[4*BlockSize:]
			src = src[4*BlockSize:]
		}
		for len(src) >= 2*BlockSize {
			a1, a2 := block2nvs(src[0:8])
			b1, b2 := block2nvs(src[8:16])
			a1, a2, b1, b2 = xcrypt32x2T16(&c.encKeys, t16, a1, a2, b1, b2)
			nvs2block(a1, a2, dst[0:8])
			nvs2block(b1, b2, dst[8:16])
			dst = dst[2*BlockSize:]
			src = src[2*BlockSize:]
		}
		for len(src) >= BlockSize {
			n1, n2 := block2nvs(src)
			n1, n2 = xcrypt32T16(&c.encKeys, t16, n1, n2)
			nvs2block(n1, n2, dst)
			dst = dst[BlockSize:]
			src = src[BlockSize:]
		}
		return
	}
	table := c.table
	t0, t1, t2, t3 := &table[0], &table[1], &table[2], &table[3]
	for len(src) >= 4*BlockSize {
		a1, a2 := block2nvs(src[0:8])
		b1, b2 := block2nvs(src[8:16])
		c1, c2 := block2nvs(src[16:24])
		d1, d2 := block2nvs(src[24:32])
		a1, a2, b1, b2, c1, c2, d1, d2 = xcrypt32x4EncryptRows(&c.baseKeys, t0, t1, t2, t3, a1, a2, b1, b2, c1, c2, d1, d2)
		nvs2block(a1, a2, dst[0:8])
		nvs2block(b1, b2, dst[8:16])
		nvs2block(c1, c2, dst[16:24])
		nvs2block(d1, d2, dst[24:32])
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= 2*BlockSize {
		a1, a2 := block2nvs(src[0:8])
		b1, b2 := block2nvs(src[8:16])
		a1, a2, b1, b2 = xcrypt32x2(&c.encKeys, table, a1, a2, b1, b2)
		nvs2block(a1, a2, dst[0:8])
		nvs2block(b1, b2, dst[8:16])
		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}
	for len(src) >= BlockSize {
		n1, n2 := block2nvs(src)
		n1, n2 = xcrypt32Encrypt(&c.baseKeys, table, n1, n2)
		nvs2block(n1, n2, dst)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

func xcrypt32x2(keys *[32]nv, table *[4][256]nv, a1, a2, b1, b2 nv) (nv, nv, nv, nv) {
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = sboxLookup(table, a1+k)^a2, a1
		b1, b2 = sboxLookup(table, b1+k)^b2, b1
	}
	return a1, a2, b1, b2
}
