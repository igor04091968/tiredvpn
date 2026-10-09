package modes

import "unsafe"

func load64(b []byte) uint64 {
	_ = b[7]
	return *(*uint64)(unsafe.Pointer(&b[0]))
}

func store64(b []byte, v uint64) {
	_ = b[7]
	*(*uint64)(unsafe.Pointer(&b[0])) = v
}

func xorIntoBlock(dst, a, b []byte, blockSize int) {
	switch blockSize {
	case 8:
		store64(dst, load64(a)^load64(b))
	case 16:
		store64(dst[0:8], load64(a[0:8])^load64(b[0:8]))
		store64(dst[8:16], load64(a[8:16])^load64(b[8:16]))
	default:
		xorInto(dst, a, b)
	}
}

func xorStream(dst, src, gamma []byte) {
	switch len(gamma) {
	case 8:
		store64(dst, load64(src)^load64(gamma))
	case 16:
		store64(dst[0:8], load64(src[0:8])^load64(gamma[0:8]))
		store64(dst[8:16], load64(src[8:16])^load64(gamma[8:16]))
	default:
		for i := range gamma {
			dst[i] = src[i] ^ gamma[i]
		}
	}
}

func xorPartial(dst, src, gamma []byte) {
	for i := range src {
		dst[i] = src[i] ^ gamma[i]
	}
}

func xorBlocksInPlace(dst, src []byte, blockSize int) {
	switch blockSize {
	case 8:
		for len(dst) >= 32 {
			store64(dst[0:8], load64(dst[0:8])^load64(src[0:8]))
			store64(dst[8:16], load64(dst[8:16])^load64(src[8:16]))
			store64(dst[16:24], load64(dst[16:24])^load64(src[16:24]))
			store64(dst[24:32], load64(dst[24:32])^load64(src[24:32]))
			dst = dst[32:]
			src = src[32:]
		}
		for len(dst) >= 8 {
			store64(dst, load64(dst)^load64(src))
			dst = dst[8:]
			src = src[8:]
		}
	case 16:
		for len(dst) >= 64 {
			store64(dst[0:8], load64(dst[0:8])^load64(src[0:8]))
			store64(dst[8:16], load64(dst[8:16])^load64(src[8:16]))
			store64(dst[16:24], load64(dst[16:24])^load64(src[16:24]))
			store64(dst[24:32], load64(dst[24:32])^load64(src[24:32]))
			store64(dst[32:40], load64(dst[32:40])^load64(src[32:40]))
			store64(dst[40:48], load64(dst[40:48])^load64(src[40:48]))
			store64(dst[48:56], load64(dst[48:56])^load64(src[48:56]))
			store64(dst[56:64], load64(dst[56:64])^load64(src[56:64]))
			dst = dst[64:]
			src = src[64:]
		}
		for len(dst) >= 16 {
			store64(dst[0:8], load64(dst[0:8])^load64(src[0:8]))
			store64(dst[8:16], load64(dst[8:16])^load64(src[8:16]))
			dst = dst[16:]
			src = src[16:]
		}
	default:
		for len(dst) >= blockSize {
			xorIntoBlock(dst[:blockSize], dst[:blockSize], src[:blockSize], blockSize)
			dst = dst[blockSize:]
			src = src[blockSize:]
		}
	}
}

func xorCBCDecryptedChunk(dst, ciphertext, prev []byte, blockSize int) {
	if len(dst) == 0 {
		return
	}
	xorIntoBlock(dst[:blockSize], dst[:blockSize], prev, blockSize)
	if len(dst) == blockSize {
		return
	}
	xorBlocksInPlace(dst[blockSize:], ciphertext[:len(dst)-blockSize], blockSize)
}

func xorOneBlockOrPartial(dst, src, gamma []byte, n int) {
	switch n {
	case 8:
		store64(dst, load64(src)^load64(gamma))
	case 16:
		store64(dst[0:8], load64(src[0:8])^load64(gamma[0:8]))
		store64(dst[8:16], load64(src[8:16])^load64(gamma[8:16]))
	default:
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ gamma[i]
		}
	}
}
