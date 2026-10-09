//go:build amd64 && !purego

package yescrypt

// xorWords XORs n uint64 words. All yescrypt callers pass a positive multiple
// of eight, allowing the assembly loop to process four XMM registers at once.
//
//go:noescape
func xorWords(dst, src []uint64, n int)
