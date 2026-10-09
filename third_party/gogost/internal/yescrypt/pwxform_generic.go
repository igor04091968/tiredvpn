//go:build !amd64 || purego

package yescrypt

func pwxform(x *[pwxWords]uint64, ctx *pwxformCtx) {
	pwxformGeneric(x, ctx)
}
