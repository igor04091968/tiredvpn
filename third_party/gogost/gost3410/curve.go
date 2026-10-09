package gost3410

import (
	"errors"
	"math/big"
	"sync"
)

var (
	zero    *big.Int = big.NewInt(0)
	bigInt1 *big.Int = big.NewInt(1)
	bigInt2 *big.Int = big.NewInt(2)
	bigInt3 *big.Int = big.NewInt(3)
	bigInt4 *big.Int = big.NewInt(4)

	pseudoMersenne256Prime = func() *big.Int {
		value := new(big.Int).Lsh(big.NewInt(1), 256)
		return value.Sub(value, big.NewInt(617))
	}()
	pseudoMersenne256Mask = func() *big.Int {
		value := new(big.Int).Lsh(big.NewInt(1), 256)
		return value.Sub(value, big.NewInt(1))
	}()
	pseudoMersenne256Factor = big.NewInt(617)
)

// Curve описывает параметры кривой ГОСТ Р 34.10 в форме Вейерштрасса
// и, если они заданы стандартом, коэффициенты скрученной формы Эдвардса.
type Curve struct {
	P *big.Int // Характеристика простого поля.
	Q *big.Int // Порядок подгруппы эллиптической кривой.

	Co *big.Int // Кофактор.

	// Коэффициенты уравнения Вейерштрасса.
	A *big.Int
	B *big.Int

	// Коэффициенты уравнения скрученной формы Эдвардса.
	E *big.Int
	D *big.Int

	// Координаты базовой точки.
	X *big.Int
	Y *big.Int

	// Кэшированные параметры s/t для преобразования точек Эдвардса.
	edS *big.Int
	edT *big.Int

	baseState  *basePrecomputeState
	fixedState *fixedBackendState
	fastModP   bool

	Name string // Человекочитаемый идентификатор кривой.
}

// NewCurve проверяет явные доменные параметры и создаёт кривую.
func NewCurve(p, q, a, b, x, y, e, d, co *big.Int) (*Curve, error) {
	c := Curve{
		Name: "unknown",
		P:    p,
		Q:    q,
		A:    a,
		B:    b,
		X:    x,
		Y:    y,
	}
	if !c.Contains(c.X, c.Y) {
		return nil, errors.New("gogost/gost3410: Некорректные параметры кривой")
	}
	if e != nil && d != nil {
		c.E = e
		c.D = d
	}
	if co == nil {
		c.Co = bigInt1
	} else {
		c.Co = co
	}
	c.fastModP = c.P.Cmp(pseudoMersenne256Prime) == 0
	c.baseState = newBasePrecomputeState(&c)
	return &c, nil
}

// curveDomain is an immutable snapshot of the parameters used to construct a
// base-point precomputation. Curve exposes its parameters as *big.Int for
// compatibility, so the snapshot also prevents a caller mutation from making
// a previously generated table silently incorrect.
type curveDomain struct {
	p, q, co, a, b, e, d, x, y big.Int
	hasE, hasD                 bool
}

func snapshotCurveDomain(c *Curve) curveDomain {
	var domain curveDomain
	domain.p.Set(c.P)
	domain.q.Set(c.Q)
	domain.co.Set(c.Co)
	domain.a.Set(c.A)
	domain.b.Set(c.B)
	domain.x.Set(c.X)
	domain.y.Set(c.Y)
	if c.E != nil {
		domain.e.Set(c.E)
		domain.hasE = true
	}
	if c.D != nil {
		domain.d.Set(c.D)
		domain.hasD = true
	}
	return domain
}

func (d *curveDomain) matches(c *Curve) bool {
	if c == nil || c.P == nil || c.Q == nil || c.Co == nil || c.A == nil ||
		c.B == nil || c.X == nil || c.Y == nil {
		return false
	}
	if d.p.Cmp(c.P) != 0 || d.q.Cmp(c.Q) != 0 || d.co.Cmp(c.Co) != 0 ||
		d.a.Cmp(c.A) != 0 || d.b.Cmp(c.B) != 0 || d.x.Cmp(c.X) != 0 ||
		d.y.Cmp(c.Y) != 0 {
		return false
	}
	if d.hasE != (c.E != nil) || d.hasD != (c.D != nil) {
		return false
	}
	return (!d.hasE || d.e.Cmp(c.E) == 0) && (!d.hasD || d.d.Cmp(c.D) == 0)
}

func (d *curveDomain) curve() Curve {
	c := Curve{
		P:        &d.p,
		Q:        &d.q,
		Co:       &d.co,
		A:        &d.a,
		B:        &d.b,
		X:        &d.x,
		Y:        &d.y,
		fastModP: d.p.Cmp(pseudoMersenne256Prime) == 0,
	}
	if d.hasE {
		c.E = &d.e
	}
	if d.hasD {
		c.D = &d.d
	}
	return c
}

type basePrecompute struct {
	table [16]jacobianPoint
	comb  [][16]jacobianPoint
}

type basePrecomputeState struct {
	domain curveDomain
	once   sync.Once
	value  *basePrecompute
}

func newBasePrecomputeState(c *Curve) *basePrecomputeState {
	return &basePrecomputeState{domain: snapshotCurveDomain(c)}
}

func (s *basePrecomputeState) get(c *Curve) *basePrecompute {
	if s == nil || !s.domain.matches(c) {
		return nil
	}
	s.once.Do(func() {
		work := s.domain.curve()
		s.value = buildBasePrecompute(&work)
	})
	return s.value
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

// clone preserves the historical factory contract: callers receive
// independent, mutable domain parameters. Only the immutable private
// precomputation state is shared.
func (c *Curve) clone() *Curve {
	return &Curve{
		P:          cloneBigInt(c.P),
		Q:          cloneBigInt(c.Q),
		Co:         cloneBigInt(c.Co),
		A:          cloneBigInt(c.A),
		B:          cloneBigInt(c.B),
		E:          cloneBigInt(c.E),
		D:          cloneBigInt(c.D),
		X:          cloneBigInt(c.X),
		Y:          cloneBigInt(c.Y),
		baseState:  c.baseState,
		fixedState: c.fixedState,
		fastModP:   c.fastModP,
		Name:       c.Name,
	}
}

func cachedCurveFactory(build func() *Curve) func() *Curve {
	var once sync.Once
	var canonical *Curve
	return func() *Curve {
		once.Do(func() {
			canonical = build()
			// Only the package's immutable, named parameter sets are admitted to
			// the fixed-limb backend. Exported NewCurve remains the compatibility
			// path for arbitrary domains.
			if fixedBackendEnabled && canonical != nil && canonical.Name != "unknown" {
				canonical.fixedState = newFixedBackendState(canonical)
			}
		})
		return canonical.clone()
	}
}

// Contains сообщает, принадлежит ли точка (x, y) этой кривой.
func (c *Curve) Contains(x, y *big.Int) bool {
	if result, used := c.fixedState.contains(c, x, y); used {
		return result
	}
	r1 := big.NewInt(0)
	r2 := big.NewInt(0)
	r1.Mul(y, y)
	r1.Mod(r1, c.P)
	r2.Mul(x, x)
	r2.Add(r2, c.A)
	r2.Mul(r2, x)
	r2.Add(r2, c.B)
	r2.Mod(r2, c.P)
	c.pos(r2)
	return r1.Cmp(r2) == 0
}

// PointSize возвращает размер координаты в байтах: 32 для 256-битных кривых
// и 64 для 512-битных кривых.
func (c *Curve) PointSize() int {
	return pointSize(c.P)
}

func (c *Curve) pos(v *big.Int) {
	if v.Cmp(zero) < 0 {
		v.Add(v, c.P)
	}
}

func (c *Curve) add(p1x, p1y, p2x, p2y *big.Int) {
	var t, tx, ty big.Int
	if p1x.Cmp(p2x) == 0 && p1y.Cmp(p2y) == 0 {
		// Удвоение точки.
		t.Mul(p1x, p1x)
		t.Mul(&t, bigInt3)
		t.Add(&t, c.A)
		tx.Mul(bigInt2, p1y)
		tx.ModInverse(&tx, c.P)
		t.Mul(&t, &tx)
		t.Mod(&t, c.P)
	} else {
		tx.Sub(p2x, p1x)
		tx.Mod(&tx, c.P)
		c.pos(&tx)
		ty.Sub(p2y, p1y)
		ty.Mod(&ty, c.P)
		c.pos(&ty)
		t.ModInverse(&tx, c.P)
		t.Mul(&t, &ty)
		t.Mod(&t, c.P)
	}
	tx.Mul(&t, &t)
	tx.Sub(&tx, p1x)
	tx.Sub(&tx, p2x)
	tx.Mod(&tx, c.P)
	c.pos(&tx)
	ty.Sub(p1x, &tx)
	ty.Mul(&ty, &t)
	ty.Sub(&ty, p1y)
	ty.Mod(&ty, c.P)
	c.pos(&ty)
	p1x.Set(&tx)
	p1y.Set(&ty)
}

type jacobianPoint struct {
	x, y, z big.Int
}

type jacobianScratch struct {
	xx, yy, yyyy, zz, s, m, t, tmp, z3 big.Int
	z1z1, z2z2, u1, u2, s1, s2         big.Int
	h, i, j, r, v, x3, y3, twoV, s1j   big.Int
	reduceHigh                         big.Int
	modReady, usePseudoMersenne        bool
}

func (p *jacobianPoint) setInfinity() {
	p.x.SetInt64(0)
	p.y.SetInt64(1)
	p.z.SetInt64(0)
}

func (p *jacobianPoint) isInfinity() bool {
	return p.z.Sign() == 0
}

func (p *jacobianPoint) setAffine(x, y *big.Int) {
	p.x.Set(x)
	p.y.Set(y)
	p.z.SetInt64(1)
}

func (p *jacobianPoint) set(q *jacobianPoint) {
	p.x.Set(&q.x)
	p.y.Set(&q.y)
	p.z.Set(&q.z)
}

func buildBasePrecompute(c *Curve) *basePrecompute {
	precompute := new(basePrecompute)
	var scratch jacobianScratch
	precompute.table[0].setInfinity()
	precompute.table[1].setAffine(c.X, c.Y)
	for i := 2; i < len(precompute.table); i++ {
		precompute.table[i].set(&precompute.table[i-1])
		c.jacobianAdd(&precompute.table[i], &precompute.table[1], &scratch)
	}
	windows := (c.Q.BitLen() + 3) / 4
	if windows > 0 && windows <= 128 {
		precompute.comb = make([][16]jacobianPoint, windows)
		var current jacobianPoint
		current.setAffine(c.X, c.Y)
		for window := 0; window < windows; window++ {
			precompute.comb[window][0].setInfinity()
			precompute.comb[window][1].set(&current)
			for i := 2; i < 16; i++ {
				precompute.comb[window][i].set(&precompute.comb[window][i-1])
				c.jacobianAdd(&precompute.comb[window][i], &current, &scratch)
			}
			for range 4 {
				c.jacobianDouble(&current, &scratch)
			}
		}
	}
	return precompute
}

func (c *Curve) mod(v *big.Int) {
	v.Mod(v, c.P)
	if v.Sign() < 0 {
		v.Add(v, c.P)
	}
}

func (c *Curve) modJacobian(v *big.Int, scratch *jacobianScratch) {
	if !scratch.modReady {
		// Curve parameters are intentionally public and mutable. Resolve the
		// optimized reducer once per scalar operation, after any caller mutation,
		// rather than trusting the construction-time hint unconditionally.
		scratch.usePseudoMersenne = c.fastModP && c.P.Cmp(pseudoMersenne256Prime) == 0
		scratch.modReady = true
	}
	if !scratch.usePseudoMersenne {
		c.mod(v)
		return
	}
	pseudoMersenneReduce256(v, &scratch.reduceHigh)
}

func pseudoMersenneReduce256(v, high *big.Int) {
	negative := v.Sign() < 0
	if negative {
		v.Neg(v)
	}
	// For p = 2^256 - 617, each high limb can be folded back by replacing
	// 2^256 with 617. Jacobian inputs are at most products of two field
	// elements, so this loop normally executes twice and never divides.
	for v.BitLen() > 256 {
		high.Rsh(v, 256)
		v.And(v, pseudoMersenne256Mask)
		high.Mul(high, pseudoMersenne256Factor)
		v.Add(v, high)
	}
	if v.Cmp(pseudoMersenne256Prime) >= 0 {
		v.Sub(v, pseudoMersenne256Prime)
	}
	if negative && v.Sign() != 0 {
		v.Sub(pseudoMersenne256Prime, v)
	}
}

func (c *Curve) jacobianDouble(p *jacobianPoint, scratch *jacobianScratch) {
	if p.isInfinity() || p.y.Sign() == 0 {
		p.setInfinity()
		return
	}
	xx, yy, yyyy := &scratch.xx, &scratch.yy, &scratch.yyyy
	zz, s, m := &scratch.zz, &scratch.s, &scratch.m
	t, tmp, z3 := &scratch.t, &scratch.tmp, &scratch.z3
	xx.Mul(&p.x, &p.x)
	c.modJacobian(xx, scratch)
	yy.Mul(&p.y, &p.y)
	c.modJacobian(yy, scratch)
	yyyy.Mul(yy, yy)
	c.modJacobian(yyyy, scratch)
	zz.Mul(&p.z, &p.z)
	c.modJacobian(zz, scratch)

	tmp.Add(&p.x, yy)
	c.modJacobian(tmp, scratch)
	tmp.Mul(tmp, tmp)
	tmp.Sub(tmp, xx)
	tmp.Sub(tmp, yyyy)
	s.Lsh(tmp, 1)
	c.modJacobian(s, scratch)

	m.Mul(xx, bigInt3)
	tmp.Mul(zz, zz)
	tmp.Mul(tmp, c.A)
	m.Add(m, tmp)
	c.modJacobian(m, scratch)

	t.Mul(m, m)
	tmp.Lsh(s, 1)
	t.Sub(t, tmp)
	c.modJacobian(t, scratch)

	tmp.Sub(s, t)
	tmp.Mul(tmp, m)
	yyyy.Lsh(yyyy, 3)
	tmp.Sub(tmp, yyyy)
	c.modJacobian(tmp, scratch)
	z3.Mul(&p.y, &p.z)
	z3.Lsh(z3, 1)
	c.modJacobian(z3, scratch)

	p.x.Set(t)
	p.y.Set(tmp)
	p.z.Set(z3)
}

func (c *Curve) jacobianAdd(p, q *jacobianPoint, scratch *jacobianScratch) {
	if q.isInfinity() {
		return
	}
	if p.isInfinity() {
		p.x.Set(&q.x)
		p.y.Set(&q.y)
		p.z.Set(&q.z)
		return
	}
	z1z1, z2z2 := &scratch.z1z1, &scratch.z2z2
	u1, u2 := &scratch.u1, &scratch.u2
	s1, s2 := &scratch.s1, &scratch.s2
	h, i, j := &scratch.h, &scratch.i, &scratch.j
	r, v, tmp := &scratch.r, &scratch.v, &scratch.tmp
	x3, y3, twoV, s1j := &scratch.x3, &scratch.y3, &scratch.twoV, &scratch.s1j
	z1z1.Mul(&p.z, &p.z)
	c.modJacobian(z1z1, scratch)
	z2z2.Mul(&q.z, &q.z)
	c.modJacobian(z2z2, scratch)

	u1.Mul(&p.x, z2z2)
	c.modJacobian(u1, scratch)
	u2.Mul(&q.x, z1z1)
	c.modJacobian(u2, scratch)

	s1.Mul(&q.z, z2z2)
	s1.Mul(s1, &p.y)
	c.modJacobian(s1, scratch)
	s2.Mul(&p.z, z1z1)
	s2.Mul(s2, &q.y)
	c.modJacobian(s2, scratch)

	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) != 0 {
			p.setInfinity()
			return
		}
		c.jacobianDouble(p, scratch)
		return
	}

	h.Sub(u2, u1)
	c.modJacobian(h, scratch)
	tmp.Lsh(h, 1)
	i.Mul(tmp, tmp)
	c.modJacobian(i, scratch)
	j.Mul(h, i)
	c.modJacobian(j, scratch)
	r.Sub(s2, s1)
	r.Lsh(r, 1)
	c.modJacobian(r, scratch)
	v.Mul(u1, i)
	c.modJacobian(v, scratch)

	x3.Mul(r, r)
	x3.Sub(x3, j)
	twoV.Lsh(v, 1)
	x3.Sub(x3, twoV)
	c.modJacobian(x3, scratch)

	y3.Sub(v, x3)
	y3.Mul(y3, r)
	s1j.Mul(s1, j)
	s1j.Lsh(s1j, 1)
	y3.Sub(y3, s1j)
	c.modJacobian(y3, scratch)

	tmp.Add(&p.z, &q.z)
	tmp.Mul(tmp, tmp)
	tmp.Sub(tmp, z1z1)
	tmp.Sub(tmp, z2z2)
	tmp.Mul(tmp, h)
	c.modJacobian(tmp, scratch)

	p.x.Set(x3)
	p.y.Set(y3)
	p.z.Set(tmp)
}

func (c *Curve) jacobianToAffine(p *jacobianPoint) (*big.Int, *big.Int, error) {
	if p.isInfinity() {
		return nil, nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	var zInv, zInv2, zInv3 big.Int
	if zInv.ModInverse(&p.z, c.P) == nil {
		return nil, nil, errors.New("gogost/gost3410: Необратимая точка")
	}
	zInv2.Mul(&zInv, &zInv)
	c.mod(&zInv2)
	zInv3.Mul(&zInv2, &zInv)
	c.mod(&zInv3)
	x := big.NewInt(0).Mul(&p.x, &zInv2)
	c.mod(x)
	y := big.NewInt(0).Mul(&p.y, &zInv3)
	c.mod(y)
	return x, y, nil
}

// Exp умножает точку (xS, yS) на степень degree.
func (c *Curve) Exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {
	if degree.Cmp(zero) == 0 {
		return nil, nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	// Building a full width-four table costs fourteen point additions. For
	// public small scalars (cofactors and protocol constants) a direct binary
	// chain is substantially cheaper. The legacy math/big path is already
	// variable-time; secret operations are routed through the fixed-limb
	// backend separately.
	if degree.BitLen() <= 4 {
		var result, point jacobianPoint
		var scratch jacobianScratch
		result.setInfinity()
		point.setAffine(xS, yS)
		for bit := degree.BitLen(); bit > 0; {
			bit--
			c.jacobianDouble(&result, &scratch)
			if degree.Bit(bit) != 0 {
				c.jacobianAdd(&result, &point, &scratch)
			}
		}
		return c.jacobianToAffine(&result)
	}
	if x, y, err, used := c.fixedState.expPoint(c, degree, xS, yS); used {
		return x, y, err
	}
	var result jacobianPoint
	var table [16]jacobianPoint
	var scratch jacobianScratch
	table[0].setInfinity()
	table[1].setAffine(xS, yS)
	for i := 2; i < len(table); i++ {
		table[i].set(&table[i-1])
		c.jacobianAdd(&table[i], &table[1], &scratch)
	}
	result.setInfinity()
	windows := (degree.BitLen() + 3) / 4
	for window := windows; window > 0; {
		window--
		for range 4 {
			c.jacobianDouble(&result, &scratch)
		}
		index := 0
		bitBase := window * 4
		for bit := 0; bit < 4; bit++ {
			if degree.Bit(bitBase+bit) != 0 {
				index |= 1 << bit
			}
		}
		if index != 0 {
			c.jacobianAdd(&result, &table[index], &scratch)
		}
	}
	return c.jacobianToAffine(&result)
}

func (c *Curve) expBase(degree *big.Int) (*big.Int, *big.Int, error) {
	if degree.Cmp(zero) == 0 {
		return nil, nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	if x, y, err, used := c.fixedState.expBase(c, degree); used {
		return x, y, err
	}
	precompute := c.baseState.get(c)
	if precompute == nil {
		return c.Exp(degree, c.X, c.Y)
	}
	if len(precompute.comb) != 0 {
		var result jacobianPoint
		var scratch jacobianScratch
		result.setInfinity()
		windows := (degree.BitLen() + 3) / 4
		if windows <= len(precompute.comb) {
			for window := 0; window < windows; window++ {
				idx := 0
				bitBase := window * 4
				for bit := 0; bit < 4; bit++ {
					if degree.Bit(bitBase+bit) != 0 {
						idx |= 1 << bit
					}
				}
				if idx != 0 {
					c.jacobianAdd(&result, &precompute.comb[window][idx], &scratch)
				}
			}
			return c.jacobianToAffine(&result)
		}
	}
	var result jacobianPoint
	var scratch jacobianScratch
	result.setInfinity()
	windows := (degree.BitLen() + 3) / 4
	for window := windows; window > 0; {
		window--
		for range 4 {
			c.jacobianDouble(&result, &scratch)
		}
		idx := 0
		bitBase := window * 4
		for bit := 0; bit < 4; bit++ {
			if degree.Bit(bitBase+bit) != 0 {
				idx |= 1 << bit
			}
		}
		if idx != 0 {
			c.jacobianAdd(&result, &precompute.table[idx], &scratch)
		}
	}
	return c.jacobianToAffine(&result)
}

func (c *Curve) expDoubleBaseAndPoint(baseScalar, pointScalar, x, y *big.Int) (*big.Int, *big.Int, error) {
	if baseScalar.Cmp(zero) == 0 && pointScalar.Cmp(zero) == 0 {
		return nil, nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	if resultX, resultY, err, used := c.fixedState.expDoublePublic(c, baseScalar, pointScalar, x, y); used {
		return resultX, resultY, err
	}
	var result jacobianPoint
	var baseTable, pointTable [4]jacobianPoint
	var joint [16]jacobianPoint
	var scratch jacobianScratch
	result.setInfinity()
	baseTable[0].setInfinity()
	baseTable[1].setAffine(c.X, c.Y)
	baseTable[2].set(&baseTable[1])
	c.jacobianDouble(&baseTable[2], &scratch)
	baseTable[3].set(&baseTable[2])
	c.jacobianAdd(&baseTable[3], &baseTable[1], &scratch)
	pointTable[0].setInfinity()
	pointTable[1].setAffine(x, y)
	pointTable[2].set(&pointTable[1])
	c.jacobianDouble(&pointTable[2], &scratch)
	pointTable[3].set(&pointTable[2])
	c.jacobianAdd(&pointTable[3], &pointTable[1], &scratch)
	for pointIndex := range pointTable {
		for baseIndex := range baseTable {
			index := baseIndex | pointIndex<<2
			switch {
			case baseIndex == 0:
				joint[index].set(&pointTable[pointIndex])
			case pointIndex == 0:
				joint[index].set(&baseTable[baseIndex])
			default:
				joint[index].set(&baseTable[baseIndex])
				c.jacobianAdd(&joint[index], &pointTable[pointIndex], &scratch)
			}
		}
	}

	bits := baseScalar.BitLen()
	if pointScalar.BitLen() > bits {
		bits = pointScalar.BitLen()
	}
	windows := (bits + 1) / 2
	for window := windows; window > 0; {
		window--
		for range 2 {
			c.jacobianDouble(&result, &scratch)
		}
		bitBase := window * 2
		baseIndex := int(baseScalar.Bit(bitBase)) | int(baseScalar.Bit(bitBase+1))<<1
		pointIndex := int(pointScalar.Bit(bitBase)) | int(pointScalar.Bit(bitBase+1))<<1
		index := baseIndex | pointIndex<<2
		if index != 0 {
			c.jacobianAdd(&result, &joint[index], &scratch)
		}
	}
	return c.jacobianToAffine(&result)
}

// Equal сообщает, совпадают ли доменные параметры двух кривых.
func (our *Curve) Equal(their *Curve) bool {
	return our.P.Cmp(their.P) == 0 &&
		our.Q.Cmp(their.Q) == 0 &&
		our.A.Cmp(their.A) == 0 &&
		our.B.Cmp(their.B) == 0 &&
		our.X.Cmp(their.X) == 0 &&
		our.Y.Cmp(their.Y) == 0 &&
		((our.E == nil && their.E == nil) || our.E.Cmp(their.E) == 0) &&
		((our.D == nil && their.D == nil) || our.D.Cmp(their.D) == 0) &&
		our.Co.Cmp(their.Co) == 0
}

// String возвращает имя кривой.
func (c *Curve) String() string {
	return c.Name
}
