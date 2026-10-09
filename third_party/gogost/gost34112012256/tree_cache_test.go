package gost34112012256

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func deriveTLSReference(params TLSTreeParams, root []byte, sequence uint64) []byte {
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], sequence&params[0])
	level1 := NewKDF(root).Derive(nil, kdfLevel1, seed[:])
	binary.BigEndian.PutUint64(seed[:], sequence&params[1])
	level2 := NewKDF(level1).Derive(nil, kdfLevel2, seed[:])
	binary.BigEndian.PutUint64(seed[:], sequence&params[2])
	return NewKDF(level2).Derive(nil, kdfLevel3, seed[:])
}

func TestTLSTreeHierarchicalCacheAgainstReference(t *testing.T) {
	root := make([]byte, Size)
	for i := range root {
		root[i] = byte(i*13 + 5)
	}
	sequences := []uint64{0, 0, 1, 1}
	for bit := uint(1); bit < 64; bit++ {
		boundary := uint64(1) << bit
		sequences = append(sequences, boundary-1, boundary, boundary+1)
	}
	sequences = append(sequences, ^uint64(0), 7, 7, 0)

	paramsList := []TLSTreeParams{
		TLSGOSTR341112256WithMagmaCTROMAC,
		TLSGOSTR341112256WithKuznyechikCTROMAC,
		TLSGOSTR341112256WithKuznyechikMGML,
		TLSGOSTR341112256WithMagmaMGML,
		TLSGOSTR341112256WithKuznyechikMGMS,
		TLSGOSTR341112256WithMagmaMGMS,
	}
	for _, params := range paramsList {
		tree := NewTLSTree(params, root)
		var previous TLSTreeParams
		initialized := false
		for _, sequence := range sequences {
			masked := TLSTreeParams{
				sequence & params[0],
				sequence & params[1],
				sequence & params[2],
			}
			wantCached := initialized && sequence > 0 && masked == previous
			got, cached := tree.DeriveCached(sequence)
			want := deriveTLSReference(params, root, sequence)
			if !bytes.Equal(got, want) {
				t.Fatalf("params=%x sequence=%d: derived key mismatch", params, sequence)
			}
			if cached != wantCached {
				t.Fatalf("params=%x sequence=%d: cached=%v, want %v", params, sequence, cached, wantCached)
			}
			previous = masked
			initialized = true
		}
	}
}

func TestTLSTreeReset(t *testing.T) {
	firstRoot := bytes.Repeat([]byte{0x11}, Size)
	secondRoot := bytes.Repeat([]byte{0xa7}, Size)
	tree := NewTLSTree(TLSGOSTR341112256WithKuznyechikMGML, firstRoot)
	_ = tree.Derive(123456)
	tree.Reset(TLSGOSTR341112256WithMagmaMGMS, secondRoot)
	for _, sequence := range []uint64{0, 1, 127, 128, 1 << 33} {
		got, cached := tree.DeriveCached(sequence)
		if cached {
			t.Fatalf("first derivation after Reset reported cached for sequence %d", sequence)
		}
		want := deriveTLSReference(TLSGOSTR341112256WithMagmaMGMS, secondRoot, sequence)
		if !bytes.Equal(got, want) {
			t.Fatalf("Reset derivation differs for sequence %d", sequence)
		}
		tree.Reset(TLSGOSTR341112256WithMagmaMGMS, secondRoot)
	}
}

func deriveESPReference(root, index []byte) []byte {
	level1 := NewKDF(root).Derive(nil, kdfLevel1, []byte{0, index[0]})
	level2 := NewKDF(level1).Derive(nil, kdfLevel2, index[1:3])
	return NewKDF(level2).Derive(nil, kdfLevel3, index[3:5])
}

func TestESPTreeHierarchicalCacheAgainstReference(t *testing.T) {
	root := make([]byte, Size)
	for i := range root {
		root[i] = byte(i*19 + 11)
	}
	indexes := [][5]byte{
		{}, {},
		{0, 0, 0, 0, 1}, {0, 0, 0, 0, 1},
		{0, 0, 1, 0, 1}, {0, 0, 1, 0, 2},
		{1, 0, 1, 0, 2}, {1, 0xff, 0xff, 0xff, 0xff},
		{0, 0, 1, 0, 2}, {},
	}
	tree := NewESPTree(root)
	previous := [5]byte{}
	for _, index := range indexes {
		wantCached := index == previous
		got, cached := tree.DeriveCached(index[:])
		want := deriveESPReference(root, index[:])
		if !bytes.Equal(got, want) {
			t.Fatalf("index=%x: derived key mismatch", index)
		}
		if cached != wantCached {
			t.Fatalf("index=%x: cached=%v, want %v", index, cached, wantCached)
		}
		previous = index
	}
}
