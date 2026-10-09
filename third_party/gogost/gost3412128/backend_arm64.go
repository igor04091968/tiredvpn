//go:build arm64 && !purego
// +build arm64,!purego

package gost3412128

func selectStreamBackend() streamBackend {
	return streamBackend{name: "arm64"}
}

//go:noescape
func encryptBlockARM64(dst, src *[16]uint8, rkeys *[10][16]uint8)

//go:noescape
func decryptBlockARM64(dst, src *[16]uint8, rkeys *[10][16]uint8)

//go:noescape
func xorKeyStreamARM64Blocks(buf []byte, iv uint64, rkeys *[10][16]byte)

//go:noescape
func xorKeyStreamARM64Blocks4(buf []byte, iv uint64, rkeys *[10][16]byte)

func encryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	encryptBlockARM64(dst, src, rkeys)
}

func decryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	decryptBlockARM64(dst, src, rkeys)
}

func xorKeyStreamInPlaceBackend(buf []byte, iv uint64, rkeys *[10][16]byte) {
	xorKeyStreamInPlaceARM64(buf, iv, rkeys)
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

func xorKeyStreamInPlaceARM64(buf []byte, iv uint64, rkeys *[10][16]byte) {
	quadLen := len(buf) &^ (4*BlockSize - 1)
	if quadLen > 0 {
		xorKeyStreamARM64Blocks4(buf[:quadLen], iv, rkeys)
		iv += uint64(quadLen / BlockSize)
	}
	buf = buf[quadLen:]

	fullLen := len(buf) &^ (BlockSize - 1)
	if fullLen > 0 {
		xorKeyStreamARM64Blocks(buf[:fullLen], iv, rkeys)
		iv += uint64(fullLen / BlockSize)
	}
	buf = buf[fullLen:]
	if len(buf) == 0 {
		return
	}

	var counterBlock, streamBlock [BlockSize]byte

	putCounterBlock(&counterBlock, iv)
	encryptBlockARM64(&streamBlock, &counterBlock, rkeys)
	for i := range buf {
		buf[i] ^= streamBlock[i]
	}
}
