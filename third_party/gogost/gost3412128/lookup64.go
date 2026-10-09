package gost3412128

func lookupTableBlock64(dst, src *[BlockSize]byte, table *[16][256]lookupBlock64) {
	entry := &table[0][src[0]]
	lo := entry.lo
	hi := entry.hi

	entry = &table[1][src[1]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[2][src[2]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[3][src[3]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[4][src[4]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[5][src[5]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[6][src[6]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[7][src[7]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[8][src[8]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[9][src[9]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[10][src[10]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[11][src[11]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[12][src[12]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[13][src[13]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[14][src[14]]
	lo ^= entry.lo
	hi ^= entry.hi
	entry = &table[15][src[15]]
	lo ^= entry.lo
	hi ^= entry.hi

	putBlock64(dst, lo, hi)
}

func lookupTableWords64(lo, hi uint64, table *[16][256]lookupBlock64) (uint64, uint64) {
	entry := &table[0][byte(lo)]
	outLo := entry.lo
	outHi := entry.hi

	entry = &table[1][byte(lo>>8)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[2][byte(lo>>16)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[3][byte(lo>>24)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[4][byte(lo>>32)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[5][byte(lo>>40)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[6][byte(lo>>48)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[7][byte(lo>>56)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[8][byte(hi)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[9][byte(hi>>8)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[10][byte(hi>>16)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[11][byte(hi>>24)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[12][byte(hi>>32)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[13][byte(hi>>40)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[14][byte(hi>>48)]
	outLo ^= entry.lo
	outHi ^= entry.hi
	entry = &table[15][byte(hi>>56)]
	outLo ^= entry.lo
	outHi ^= entry.hi

	return outLo, outHi
}
