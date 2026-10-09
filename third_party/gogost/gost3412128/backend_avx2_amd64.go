//go:build amd64 && !purego
// +build amd64,!purego

package gost3412128

//go:noescape
func xorKeyStreamAVX2Blocks4(buf []byte, iv uint64, rkeys *[10][16]byte)

func xorKeyStreamInPlaceAVX2(buf []byte, iv uint64, rkeys *[10][16]byte) {
	quadLen := len(buf) &^ (4*BlockSize - 1)
	if quadLen > 0 {
		xorKeyStreamAVX2Blocks4(buf[:quadLen], iv, rkeys)
		iv += uint64(quadLen / BlockSize)
	}
	if quadLen < len(buf) {
		xorKeyStreamInPlaceSSE(buf[quadLen:], iv, rkeys)
	}
}
