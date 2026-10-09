// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
	"runtime"
	"sync"
	"weak"
)

// weakCertCache provides a cache of parsed certificates, allowing multiple
// connections to reuse the expensive parse while retaining no strong roots.
type weakCertCache struct{ sync.Map }

func (wcc *weakCertCache) newCert(der []byte) (*x509.Certificate, error) {
	if entry, ok := wcc.Load(string(der)); ok {
		if cert := entry.(weak.Pointer[x509.Certificate]).Value(); cert != nil {
			return cert, nil
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	wp := weak.Make(cert)
	if entry, loaded := wcc.LoadOrStore(string(der), wp); !loaded {
		runtime.AddCleanup(cert, func(_ any) { wcc.CompareAndDelete(string(der), entry) }, any(string(der)))
	} else if existing := entry.(weak.Pointer[x509.Certificate]).Value(); existing != nil {
		return existing, nil
	} else if wcc.CompareAndSwap(string(der), entry, wp) {
		runtime.AddCleanup(cert, func(_ any) { wcc.CompareAndDelete(string(der), wp) }, any(string(der)))
	}
	return cert, nil
}

var globalCertCache = new(weakCertCache)
