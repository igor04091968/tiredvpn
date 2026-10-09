//go:build amd64 && !purego

package yescrypt

import (
	"math/rand"
	"testing"
)

func TestPwxformAMD64MatchesGeneric(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	for initialW := uint32(0); initialW < sTableLen; initialW += 32 {
		var xGeneric, xAMD64 [pwxWords]uint64
		var tablesGeneric, tablesAMD64 [3]sTable
		for i := range xGeneric {
			xGeneric[i] = rng.Uint64()
		}
		xAMD64 = xGeneric
		for table := range tablesGeneric {
			for i := range tablesGeneric[table] {
				tablesGeneric[table][i] = rng.Uint64()
			}
			tablesAMD64[table] = tablesGeneric[table]
		}

		genericCtx := pwxformCtx{
			s0: &tablesGeneric[0],
			s1: &tablesGeneric[1],
			s2: &tablesGeneric[2],
			w:  initialW,
		}
		amd64Ctx := pwxformCtx{
			s0: &tablesAMD64[0],
			s1: &tablesAMD64[1],
			s2: &tablesAMD64[2],
			w:  initialW,
		}

		for iteration := range 24 {
			pwxformGeneric(&xGeneric, &genericCtx)
			pwxform(&xAMD64, &amd64Ctx)

			if xAMD64 != xGeneric {
				t.Fatalf("w=%d iteration=%d: X differs", initialW, iteration)
			}
			if tablesAMD64 != tablesGeneric {
				t.Fatalf("w=%d iteration=%d: S tables differ", initialW, iteration)
			}
			if amd64Ctx.w != genericCtx.w {
				t.Fatalf("w=%d iteration=%d: ctx.w=%d, want %d", initialW, iteration, amd64Ctx.w, genericCtx.w)
			}
			if tablePosition(&amd64Ctx, &tablesAMD64) != tablePosition(&genericCtx, &tablesGeneric) {
				t.Fatalf("w=%d iteration=%d: S-table rotation differs", initialW, iteration)
			}
		}
	}
}

func tablePosition(ctx *pwxformCtx, tables *[3]sTable) [3]int {
	position := func(table *sTable) int {
		for i := range tables {
			if table == &tables[i] {
				return i
			}
		}
		return -1
	}
	return [3]int{position(ctx.s0), position(ctx.s1), position(ctx.s2)}
}
