//go:build !gostcttrace

package gost3410

// These no-op hooks are inlined away in production builds. The gostcttrace
// variant replaces them with counters used to verify that secret scalar
// multiplication follows the same field/point operation trace.
func fixedTraceFieldAdd()      {}
func fixedTraceFieldSub()      {}
func fixedTraceFieldMul()      {}
func fixedTraceFieldSquare()   {}
func fixedTraceFieldInvert()   {}
func fixedTracePointAdd()      {}
func fixedTracePointDouble()   {}
func fixedTraceProjectiveAdd() {}
func fixedTraceEdwardsAdd()    {}
func fixedTraceEdwardsDouble() {}
