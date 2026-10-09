package gost341264

type magmaT16Table [2][1 << 16]word

var magmaT16 = makeMagmaT16Table(&magmaTable)

func makeMagmaT16Table(table *[4][256]word) *magmaT16Table {
	t := new(magmaT16Table)
	for i := range 1 << 16 {
		t[0][i] = table[0][byte(i)] ^ table[1][byte(i>>8)]
		t[1][i] = table[2][byte(i)] ^ table[3][byte(i>>8)]
	}
	return t
}

func magmaT16Lookup(lo, hi *[1 << 16]word, n word) word {
	return lo[uint16(n)] ^ hi[uint16(n>>16)]
}

func magmaCrypt32T16(keys *[32]word, table *magmaT16Table, n1, n2 word) (word, word) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		n1, n2 = magmaT16Lookup(lo, hi, n1+keys[i])^n2, n1
	}
	return n1, n2
}

func magmaCrypt32EncryptT16(keys *[8]word, table *magmaT16Table, n1, n2 word) (word, word) {
	lo, hi := &table[0], &table[1]
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	return n1, n2
}

func magmaCrypt32DecryptT16(keys *[8]word, table *magmaT16Table, n1, n2 word) (word, word) {
	lo, hi := &table[0], &table[1]
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1

	n1, n2 = magmaT16Lookup(lo, hi, n1+k7)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k6)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k5)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k4)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k3)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k2)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k1)^n2, n1
	n1, n2 = magmaT16Lookup(lo, hi, n1+k0)^n2, n1
	return n1, n2
}

func magmaCrypt32x2T16(keys *[32]word, table *magmaT16Table, a1, a2, b1, b2 word) (word, word, word, word) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = magmaT16Lookup(lo, hi, a1+k)^a2, a1
		b1, b2 = magmaT16Lookup(lo, hi, b1+k)^b2, b1
	}
	return a1, a2, b1, b2
}

func magmaCrypt32x4T16(keys *[32]word, table *magmaT16Table, a1, a2, b1, b2, c1, c2, d1, d2 word) (word, word, word, word, word, word, word, word) {
	lo, hi := &table[0], &table[1]
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = magmaT16Lookup(lo, hi, a1+k)^a2, a1
		b1, b2 = magmaT16Lookup(lo, hi, b1+k)^b2, b1
		c1, c2 = magmaT16Lookup(lo, hi, c1+k)^c2, c1
		d1, d2 = magmaT16Lookup(lo, hi, d1+k)^d2, d1
	}
	return a1, a2, b1, b2, c1, c2, d1, d2
}
