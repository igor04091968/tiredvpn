//go:build amd64 && !purego
// +build amd64,!purego

package gost3412128

func selectStreamBackend() streamBackend {
	if hasAVX2() {
		return streamBackend{name: "avx2"}
	}
	return streamBackend{name: "sse"}
}

var useAVX2StreamBackend = activeStreamBackend.name == "avx2"

//go:noescape
func encryptBlockSSEStack(dst, src *[16]uint8, rkeys *[10][16]uint8)

//go:noescape
func decryptBlockSSEStack(dst, src *[16]uint8, rkeys *[10][16]uint8)

//go:noescape
func xorKeyStreamSSEBlocks(buf []byte, iv uint64, rkeys *[10][16]byte)

//go:noescape
func xorKeyStreamCTRAVX2Blocks4(dst, src []byte, counter *[16]byte, rkeys *[10][16]byte)

//go:noescape
func encryptBlocksAVX2Blocks4(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func encryptBlocksAVX2Blocks8(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func encryptBlocksAVX2PairLUTBlocks4(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func encryptBlocksAVX2PairLUTBlocks8(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func decryptBlocksAVX2Blocks4(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func decryptBlocksAVX2PairLUTBlocks4(dst, src []byte, rkeys *[10][16]byte)

//go:noescape
func decryptBlocksAVX2PairLUTBlocks8(dst, src []byte, rkeys *[10][16]byte)

// SSEStack остаётся стабильным single-block backend. AVX2 используется для
// многоблочных stream и ECB/bulk путей, где он стабильно быстрее.
func encryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	encryptBlockSSEStack(dst, src, rkeys)
}

func decryptBlock(dst, src *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	decryptBlockSSEStack(dst, src, rkeys)
}

func xorKeyStreamInPlaceBackend(buf []byte, iv uint64, rkeys *[10][16]byte) {
	if useAVX2StreamBackend {
		xorKeyStreamInPlaceAVX2(buf, iv, rkeys)
		return
	}
	xorKeyStreamInPlaceSSE(buf, iv, rkeys)
}

func xorKeyStreamInPlaceSSE(buf []byte, iv uint64, rkeys *[10][16]byte) {
	fullLen := len(buf) &^ (BlockSize - 1)
	if fullLen > 0 {
		xorKeyStreamSSEBlocks(buf[:fullLen], iv, rkeys)
		iv += uint64(fullLen / BlockSize)
	}
	if fullLen == len(buf) {
		return
	}

	var counterBlock, streamBlock [BlockSize]byte

	putCounterBlock(&counterBlock, iv)
	encryptBlockSSEStack(&streamBlock, &counterBlock, rkeys)
	tail := buf[fullLen:]
	for i := range tail {
		tail[i] ^= streamBlock[i]
	}
}

func xorKeyStreamCTRCounterBackend(dst, src []byte, counter *[16]byte, rkeys *[10][16]byte) {
	if useAVX2StreamBackend {
		quadLen := len(src) &^ (4*BlockSize - 1)
		if quadLen > 0 {
			xorKeyStreamCTRAVX2Blocks4(dst[:quadLen], src[:quadLen], counter, rkeys)
			addCounterHalf(counter[BlockSize/2:], quadLen/BlockSize)
		}
		if quadLen < len(src) {
			xorKeyStreamCTRCounterGeneric(dst[quadLen:], src[quadLen:], counter, rkeys)
		}
		return
	}
	xorKeyStreamCTRCounterGeneric(dst, src, counter, rkeys)
}

func encryptBlocksBackend(dst, src []byte, rkeys *[10][16]byte) int {
	if !useAVX2StreamBackend {
		return 0
	}
	if len(src) >= 8*BlockSize {
		ensureEncryptPairLookup()
		done := 0
		octLen := len(src) &^ (8*BlockSize - 1)
		if octLen > 0 {
			encryptBlocksAVX2PairLUTBlocks8(dst[:octLen], src[:octLen], rkeys)
			done = octLen
			dst = dst[octLen:]
			src = src[octLen:]
		}
		quadLen := len(src) &^ (4*BlockSize - 1)
		if quadLen > 0 {
			encryptBlocksAVX2PairLUTBlocks4(dst[:quadLen], src[:quadLen], rkeys)
			done += quadLen
		}
		return done
	}
	octLen := len(src) &^ (8*BlockSize - 1)
	if octLen > 0 {
		encryptBlocksAVX2Blocks8(dst[:octLen], src[:octLen], rkeys)
	}
	dst = dst[octLen:]
	src = src[octLen:]
	quadLen := len(src) &^ (4*BlockSize - 1)
	if quadLen > 0 {
		encryptBlocksAVX2Blocks4(dst[:quadLen], src[:quadLen], rkeys)
	}
	return octLen + quadLen
}

func encryptBlocksCompactBackend(dst, src []byte, rkeys *[10][16]byte) int {
	if !useAVX2StreamBackend {
		return 0
	}
	octLen := len(src) &^ (8*BlockSize - 1)
	if octLen > 0 {
		encryptBlocksAVX2Blocks8(dst[:octLen], src[:octLen], rkeys)
	}
	dst = dst[octLen:]
	src = src[octLen:]
	quadLen := len(src) &^ (4*BlockSize - 1)
	if quadLen > 0 {
		encryptBlocksAVX2Blocks4(dst[:quadLen], src[:quadLen], rkeys)
	}
	return octLen + quadLen
}

func decryptBlocksBackend(dst, src []byte, rkeys *[10][16]byte) int {
	if !useAVX2StreamBackend {
		return 0
	}
	if len(src) >= 8*BlockSize {
		ensureDecryptPairLookup()
		done := 0
		octLen := len(src) &^ (8*BlockSize - 1)
		if octLen > 0 {
			decryptBlocksAVX2PairLUTBlocks8(dst[:octLen], src[:octLen], rkeys)
			done = octLen
			dst = dst[octLen:]
			src = src[octLen:]
		}
		quadLen := len(src) &^ (4*BlockSize - 1)
		if quadLen > 0 {
			decryptBlocksAVX2PairLUTBlocks4(dst[:quadLen], src[:quadLen], rkeys)
			done += quadLen
		}
		return done
	}
	quadLen := len(src) &^ (4*BlockSize - 1)
	if quadLen == 0 {
		return 0
	}
	decryptBlocksAVX2Blocks4(dst[:quadLen], src[:quadLen], rkeys)
	return quadLen
}
