// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	"slices"

	"gitverse.ru/uzer_007/gogost/v3/gosttls/internal/godebug"
)

// Defaults are kept separate so distributions can apply local policy without
// changing the handshake implementation. GOST algorithms are preferred, while
// the Go 1.27 post-quantum and classical fallbacks remain enabled.

// tlsmlkem=0 restores the pre-Go 1.24 default key exchanges.
var tlsmlkem = godebug.New("tlsmlkem")

// tlssecpmlkem=0 restores the pre-Go 1.26 default key exchanges.
var tlssecpmlkem = godebug.New("tlssecpmlkem")

// defaultCurveEnabled reports whether the key exchange is enabled by default.
func defaultCurveEnabled(curve CurveID) bool {
	if isGOSTCurve(curve) {
		return true
	}
	switch curve {
	case X25519, CurveP256, CurveP384, CurveP521:
		return true
	case X25519MLKEM768:
		return tlsmlkem.Value() != "0"
	case SecP256r1MLKEM768, SecP384r1MLKEM1024:
		return tlsmlkem.Value() != "0" && tlssecpmlkem.Value() != "0"
	default:
		return false
	}
}

// curvePreferenceOrder is the fixed preference order and includes every
// implemented key exchange. GOST remains preferred for mixed configurations.
func curvePreferenceOrder() []CurveID {
	return []CurveID{
		GOSTCurve256A, GOSTCurve256B, GOSTCurve256C, GOSTCurve256D,
		GOSTCurve512C, GOSTCurve512A, GOSTCurve512B,
		X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM1024,
		X25519, CurveP256, CurveP384, CurveP521,
	}
}

func supportedCipherSuites(aesGCMPreferred bool) []uint16 {
	if aesGCMPreferred {
		return slices.Clone(cipherSuitesPreferenceOrder)
	}
	return slices.Clone(cipherSuitesPreferenceOrderNoAES)
}

func defaultCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(id uint16) bool {
		return disabledCipherSuites[id]
	})
}
