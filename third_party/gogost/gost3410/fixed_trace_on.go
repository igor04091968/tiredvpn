//go:build gostcttrace

package gost3410

import "sync/atomic"

type fixedTraceCounters struct {
	fieldAdd      atomic.Uint64
	fieldSub      atomic.Uint64
	fieldMul      atomic.Uint64
	fieldSquare   atomic.Uint64
	fieldInvert   atomic.Uint64
	pointAdd      atomic.Uint64
	pointDouble   atomic.Uint64
	projectiveAdd atomic.Uint64
	edwardsAdd    atomic.Uint64
	edwardsDouble atomic.Uint64
}

type fixedTraceSnapshot struct {
	FieldAdd      uint64
	FieldSub      uint64
	FieldMul      uint64
	FieldSquare   uint64
	FieldInvert   uint64
	PointAdd      uint64
	PointDouble   uint64
	ProjectiveAdd uint64
	EdwardsAdd    uint64
	EdwardsDouble uint64
}

var fixedTrace fixedTraceCounters

func resetFixedTrace() {
	fixedTrace.fieldAdd.Store(0)
	fixedTrace.fieldSub.Store(0)
	fixedTrace.fieldMul.Store(0)
	fixedTrace.fieldSquare.Store(0)
	fixedTrace.fieldInvert.Store(0)
	fixedTrace.pointAdd.Store(0)
	fixedTrace.pointDouble.Store(0)
	fixedTrace.projectiveAdd.Store(0)
	fixedTrace.edwardsAdd.Store(0)
	fixedTrace.edwardsDouble.Store(0)
}

func snapshotFixedTrace() fixedTraceSnapshot {
	return fixedTraceSnapshot{
		FieldAdd:      fixedTrace.fieldAdd.Load(),
		FieldSub:      fixedTrace.fieldSub.Load(),
		FieldMul:      fixedTrace.fieldMul.Load(),
		FieldSquare:   fixedTrace.fieldSquare.Load(),
		FieldInvert:   fixedTrace.fieldInvert.Load(),
		PointAdd:      fixedTrace.pointAdd.Load(),
		PointDouble:   fixedTrace.pointDouble.Load(),
		ProjectiveAdd: fixedTrace.projectiveAdd.Load(),
		EdwardsAdd:    fixedTrace.edwardsAdd.Load(),
		EdwardsDouble: fixedTrace.edwardsDouble.Load(),
	}
}

func fixedTraceFieldAdd()      { fixedTrace.fieldAdd.Add(1) }
func fixedTraceFieldSub()      { fixedTrace.fieldSub.Add(1) }
func fixedTraceFieldMul()      { fixedTrace.fieldMul.Add(1) }
func fixedTraceFieldSquare()   { fixedTrace.fieldSquare.Add(1) }
func fixedTraceFieldInvert()   { fixedTrace.fieldInvert.Add(1) }
func fixedTracePointAdd()      { fixedTrace.pointAdd.Add(1) }
func fixedTracePointDouble()   { fixedTrace.pointDouble.Add(1) }
func fixedTraceProjectiveAdd() { fixedTrace.projectiveAdd.Add(1) }
func fixedTraceEdwardsAdd()    { fixedTrace.edwardsAdd.Add(1) }
func fixedTraceEdwardsDouble() { fixedTrace.edwardsDouble.Add(1) }
