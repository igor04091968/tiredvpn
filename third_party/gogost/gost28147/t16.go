package gost28147

type t16Table [2][1 << 16]nv

var (
	sboxT16Test       = makeT16Table(&sboxTableTest)
	sboxT16CryptoProA = makeT16Table(&sboxTableCryptoProA)
	sboxT16CryptoProB = makeT16Table(&sboxTableCryptoProB)
	sboxT16CryptoProC = makeT16Table(&sboxTableCryptoProC)
	sboxT16CryptoProD = makeT16Table(&sboxTableCryptoProD)
	sboxT16TC26Z      = makeT16Table(&sboxTableTC26Z)
	sboxT16R341194T   = makeT16Table(&sboxTableR341194T)
	sboxT16R341194CP  = makeT16Table(&sboxTableR341194CP)
	sboxT16EAC        = makeT16Table(&sboxTableEAC)
)

func makeT16Table(table *[4][256]nv) *t16Table {
	t := new(t16Table)
	for i := range 1 << 16 {
		t[0][i] = table[0][byte(i)] ^ table[1][byte(i>>8)]
		t[1][i] = table[2][byte(i)] ^ table[3][byte(i>>8)]
	}
	return t
}

func knownSboxT16(sbox *Sbox) *t16Table {
	switch sbox {
	case &SboxIdGost2814789TestParamSet:
		return sboxT16Test
	case &SboxIdGost2814789CryptoProAParamSet:
		return sboxT16CryptoProA
	case &SboxIdGost2814789CryptoProBParamSet:
		return sboxT16CryptoProB
	case &SboxIdGost2814789CryptoProCParamSet:
		return sboxT16CryptoProC
	case &SboxIdGost2814789CryptoProDParamSet:
		return sboxT16CryptoProD
	case &SboxIdtc26gost28147paramZ:
		return sboxT16TC26Z
	case &SboxIdGostR341194TestParamSet:
		return sboxT16R341194T
	case &SboxIdGostR341194CryptoProParamSet:
		return sboxT16R341194CP
	case &SboxEACParamSet:
		return sboxT16EAC
	default:
		return nil
	}
}

func t16Lookup(lo, hi *[1 << 16]nv, n nv) nv {
	return lo[uint16(n)] ^ hi[uint16(n>>16)]
}

func xcrypt32T16(keys *[32]nv, table *t16Table, n1, n2 nv) (nv, nv) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		n1, n2 = t16Lookup(lo, hi, n1+keys[i])^n2, n1
	}
	return n1, n2
}

func xcrypt32EncryptT16(keys *[8]nv, table *t16Table, n1, n2 nv) (nv, nv) {
	lo, hi := &table[0], &table[1]
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	return n1, n2
}

func xcrypt32DecryptT16(keys *[8]nv, table *t16Table, n1, n2 nv) (nv, nv) {
	lo, hi := &table[0], &table[1]
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1

	n1, n2 = t16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = t16Lookup(lo, hi, n1+k0)^n2, n1
	return n1, n2
}

func xcrypt32x2T16(keys *[32]nv, table *t16Table, a1, a2, b1, b2 nv) (nv, nv, nv, nv) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = t16Lookup(lo, hi, a1+k)^a2, a1
		b1, b2 = t16Lookup(lo, hi, b1+k)^b2, b1
	}
	return a1, a2, b1, b2
}

func xcrypt32x4T16(keys *[32]nv, table *t16Table, a1, a2, b1, b2, c1, c2, d1, d2 nv) (nv, nv, nv, nv, nv, nv, nv, nv) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = t16Lookup(lo, hi, a1+k)^a2, a1
		b1, b2 = t16Lookup(lo, hi, b1+k)^b2, b1
		c1, c2 = t16Lookup(lo, hi, c1+k)^c2, c1
		d1, d2 = t16Lookup(lo, hi, d1+k)^d2, d1
	}
	return a1, a2, b1, b2, c1, c2, d1, d2
}
