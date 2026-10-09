//go:build purego || (!amd64 && !arm64)
// +build purego !amd64,!arm64

package gost3412128

func selectStreamBackend() streamBackend {
	return streamBackend{name: "purego"}
}

func encryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	encryptBlockLookup(dst, src, rkeys)
}

func decryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	decryptBlockLookup(dst, src, rkeys)
}

func xorKeyStreamInPlaceBackend(buf []byte, iv uint64, rkeys *[10][16]byte) {
	xorKeyStreamInPlacePure(buf, iv, rkeys)
}

func xorKeyStreamCTRCounterBackend(dst, src []byte, counter *[16]byte, rkeys *[10][16]byte) {
	xorKeyStreamCTRCounterGeneric(dst, src, counter, rkeys)
}

func encryptBlocksBackend(dst, src []byte, rkeys *[10][16]byte) int {
	return 0
}

func encryptBlocksCompactBackend(dst, src []byte, rkeys *[10][16]byte) int {
	return 0
}

func decryptBlocksBackend(dst, src []byte, rkeys *[10][16]byte) int {
	return 0
}

func xorKeyStreamInPlacePure(buf []byte, iv uint64, rkeys *[10][16]byte) {
	var counterBlock, streamBlock [BlockSize]byte

	putCounterBlock(&counterBlock, iv)
	fullBlockCount := len(buf) / BlockSize
	tailLen := len(buf) - fullBlockCount*BlockSize

	for blockNum := 0; blockNum < fullBlockCount; blockNum++ {
		offset := blockNum * BlockSize
		encryptBlock(&streamBlock, &counterBlock, rkeys)
		xorSliceBlock(buf[offset:offset+BlockSize], &streamBlock)

		iv++
		putCounterHead(&counterBlock, iv)
	}

	if tailLen > 0 {
		encryptBlock(&streamBlock, &counterBlock, rkeys)
		tail := buf[len(buf)-tailLen:]
		for i := range tail {
			tail[i] ^= streamBlock[i]
		}
	}
}
