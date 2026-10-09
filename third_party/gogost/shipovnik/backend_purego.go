//go:build !amd64 || purego

package shipovnik

func syndrome(out, vector []byte) {
	syndromeGeneric(out, vector)
}
