// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGo127PickECHConfigRejectsExportOnlyAEAD(t *testing.T) {
	encoded, err := hex.DecodeString("0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000")
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte{0x00, 0x01, 0x00, 0x01}, []byte{0x00, 0x01, 0xff, 0xff}, 1)
	configs, err := parseECHConfigList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if config, _, _, _ := pickECHConfig(configs); config != nil {
		t.Fatalf("picked ECH config with export-only AEAD: %v", config)
	}
}

func TestGo127ECHPadding(t *testing.T) {
	const maxNameLength = 64
	for _, test := range []struct {
		name       string
		serverName string
	}{
		{"short", "a.test"},
		{"medium", strings.Repeat("a", 30) + ".test"},
		{"maximum", strings.Repeat("a", maxNameLength) + ".test"},
		{"no-sni", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := go127ECHClientHello(test.serverName)
			encoded, err := encodeInnerClientHello(inner, maxNameLength)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded)%32 != 0 {
				t.Fatalf("encoded length = %d, want a multiple of 32", len(encoded))
			}
		})
	}

	sizes := make(map[int]struct{})
	for serverNameLength := 1; serverNameLength <= maxNameLength; serverNameLength++ {
		encoded, err := encodeInnerClientHello(go127ECHClientHello(strings.Repeat("a", serverNameLength)+".test"), maxNameLength)
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(encoded)] = struct{}{}
	}
	if len(sizes) > 4 {
		t.Fatalf("got %d distinct encoded sizes, want at most 4", len(sizes))
	}
}

func go127ECHClientHello(serverName string) *clientHelloMsg {
	return &clientHelloMsg{
		vers:               VersionTLS13,
		random:             make([]byte, 32),
		serverName:         serverName,
		cipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		supportedVersions:  []uint16{VersionTLS13},
	}
}
