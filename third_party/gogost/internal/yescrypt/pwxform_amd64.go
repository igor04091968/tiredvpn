//go:build amd64 && !purego

package yescrypt

// pwxform applies the fixed yescrypt PWX transform and rotates the three S
// tables in ctx. The assembly routine only permutes pointers already held by
// ctx, so it does not introduce a new GC-reachable pointer.
//
//go:noescape
func pwxform(x *[pwxWords]uint64, ctx *pwxformCtx)
