package gost3412128

func encryptBlockLookup(dst, src *[16]uint8, rkeys *[10][16]uint8) {
	lo, hi := getBlock64(src)
	klo, khi := getBlock64(&rkeys[0])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[1])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[2])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[3])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[4])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[5])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[6])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[7])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[8])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &lsEncLookup64)
	klo, khi = getBlock64(&rkeys[9])
	putBlock64(dst, lo^klo, hi^khi)
}

func decryptBlockLookup(dst, src *[16]uint8, rkeys *[10][16]uint8) {
	lo, hi := getBlock64(src)
	lo, hi = lookupTableWords64(lo, hi, &lInvLookup64)
	klo, khi := getBlock64(&rkeys[9])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[8])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[7])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[6])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[5])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[4])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[3])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[2])
	lo, hi = lookupTableWords64(lo^klo, hi^khi, &slDecLookup64)
	klo, khi = getBlock64(&rkeys[1])
	lo ^= klo
	hi ^= khi

	dst[0] = piInverseTable[byte(lo)] ^ rkeys[0][0]
	dst[1] = piInverseTable[byte(lo>>8)] ^ rkeys[0][1]
	dst[2] = piInverseTable[byte(lo>>16)] ^ rkeys[0][2]
	dst[3] = piInverseTable[byte(lo>>24)] ^ rkeys[0][3]
	dst[4] = piInverseTable[byte(lo>>32)] ^ rkeys[0][4]
	dst[5] = piInverseTable[byte(lo>>40)] ^ rkeys[0][5]
	dst[6] = piInverseTable[byte(lo>>48)] ^ rkeys[0][6]
	dst[7] = piInverseTable[byte(lo>>56)] ^ rkeys[0][7]
	dst[8] = piInverseTable[byte(hi)] ^ rkeys[0][8]
	dst[9] = piInverseTable[byte(hi>>8)] ^ rkeys[0][9]
	dst[10] = piInverseTable[byte(hi>>16)] ^ rkeys[0][10]
	dst[11] = piInverseTable[byte(hi>>24)] ^ rkeys[0][11]
	dst[12] = piInverseTable[byte(hi>>32)] ^ rkeys[0][12]
	dst[13] = piInverseTable[byte(hi>>40)] ^ rkeys[0][13]
	dst[14] = piInverseTable[byte(hi>>48)] ^ rkeys[0][14]
	dst[15] = piInverseTable[byte(hi>>56)] ^ rkeys[0][15]
}
