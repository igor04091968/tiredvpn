//go:build gostlegacycurve

package gost3410

// gostlegacycurve is a diagnostic/benchmark build tag. It keeps the public API
// unchanged but routes named curves through the compatibility math/big path so
// end-to-end benchmarks can isolate the fixed-limb backend.
const fixedBackendEnabled = false
