// Copyright 2026 TiredVPN contributors. BSD-style license in LICENSE.
package gosttls

import (
	"encoding/binary"
	"errors"
	"slices"
)

// Reference: CryptoPro curl 8.21.0-CPRO / CSP 5.0.13820, TLS 1.3, no ALPN.
// Random/session/key bytes are fresh per handshake. Negotiation remains GOST.
// Post-handshake client auth (extension 49) is deliberately absent because this
// implementation does not support that capability.
func applyCryptoProClientHello(config *Config, hello *clientHelloMsg) error {
	if config.MinVersion != VersionTLS13 || config.MaxVersion != VersionTLS13 ||
		config.EncryptedClientHelloConfigList != nil || config.ClientSessionCache != nil ||
		len(config.NextProtos) != 0 || len(config.Certificates) != 0 || config.GetClientCertificate != nil {
		return errors.New("tls: CryptoPro profile requires TLS 1.3 without ECH, cache, ALPN or client certificates")
	}
	for _, suite := range config.cipherSuitesTLS13() {
		if !isGOSTCipherSuite(suite) {
			return errors.New("tls: CryptoPro profile requires strict GOST configuration")
		}
	}
	hello.cryptoProProfile = true
	hello.cipherSuites = []uint16{0xc104, 0xc103, 0xc106, 0xc105, 0x1301, 0x1302}
	hello.supportedCurves = []CurveID{34, 35, 36, 37, 38, 39, 40, 23, 24, 25, 29}
	// Match advertised schemes; verification still uses strict GOST config.
	hello.supportedSignatureAlgorithms = []SignatureScheme{0x0709, 0x070a, 0x070b, 0x070c, 0x070d, 0x070e, 0x070f, 0xeeee, 0x0840, 0xefef, 0x0841, 0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603}
	hello.supportedSignatureAlgorithmsCert = nil
	hello.ocspStapling = false
	hello.scts = false
	hello.ticketSupported = true
	hello.pskModes = []uint8{pskModeDHE}
	return nil
}

// Reorder before transcript hashing, never by mutating bytes in net.Conn.
// Preserve HRR's optional cookie and the mandatory last position of PSK.
func cryptoProExtensions(encoded []byte) ([]byte, error) {
	order := []uint16{65281, 35, 0, 23, 11, 10, 13, 43, 45, 51}
	fields := make(map[uint16][]byte)
	var extra []uint16
	for len(encoded) > 0 {
		if len(encoded) < 4 {
			return nil, errors.New("tls: truncated profile extension")
		}
		id, n := binary.BigEndian.Uint16(encoded), int(binary.BigEndian.Uint16(encoded[2:]))+4
		if n > len(encoded) {
			return nil, errors.New("tls: truncated profile extension data")
		}
		if _, exists := fields[id]; exists {
			return nil, errors.New("tls: duplicate profile extension")
		}
		fields[id] = encoded[:n]
		if !slices.Contains(order, id) && id != extensionPreSharedKey {
			extra = append(extra, id)
		}
		encoded = encoded[n:]
	}
	var out []byte
	for _, id := range append(order, extra...) {
		out = append(out, fields[id]...)
	}
	return append(out, fields[extensionPreSharedKey]...), nil
}
