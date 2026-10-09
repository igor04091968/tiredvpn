// Copyright 2026 gogost authors. All rights reserved.
// Use of this source code is governed by the license in the LICENSE file.

package gosttls

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

// tlsHash is deliberately local to this package. crypto.Hash cannot be
// extended by a library, and registering process-wide pseudo identifiers would
// make GOST TLS depend on global mutable state.
type tlsHash uint8

const (
	hashSHA256 tlsHash = iota + 1
	hashSHA384
	hashGOST256
)

func (h tlsHash) New() hash.Hash {
	switch h {
	case hashSHA256:
		return sha256.New()
	case hashSHA384:
		return sha512.New384()
	case hashGOST256:
		return gost34112012256.New()
	default:
		panic("gosttls: internal error: unsupported TLS hash")
	}
}

func (h tlsHash) Size() int {
	switch h {
	case hashSHA256, hashGOST256:
		return 32
	case hashSHA384:
		return 48
	default:
		panic("gosttls: internal error: unsupported TLS hash")
	}
}
