//go:build purego || (!amd64 && !arm64)

package gost3410

func fixedMulArchAvailable() bool { return false }

func fixedAddMulArch(_, _ *uint64, _ uint64, _ int) uint64 { return 0 }
