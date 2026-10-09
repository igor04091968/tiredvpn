package gost3410

import (
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"math/bits"
	"sync"
	"sync/atomic"
)

// limbs256 and limbs512 are the concrete, allocation-free representations
// used by the optimized 256- and 512-bit curve backends. Generic helpers are
// monomorphized by the compiler for these two exact array types; there is no
// interface dispatch in field or point arithmetic.
type limbs256 [4]uint64
type limbs512 [8]uint64

type fixedLimbs interface {
	limbs256 | limbs512
}

type montDomain[L fixedLimbs] struct {
	modulus    L
	modulusBig big.Int
	r2         L // R^2 mod modulus, in the ordinary representation
	one        L // 1 in Montgomery representation
	minus2     L // modulus-2, ordinary representation (public exponent)
	m0Inv      uint64
	pseudo256  bool
	archMul    bool
}

func newMontDomain[L fixedLimbs](modulus *big.Int) (montDomain[L], bool) {
	var domain montDomain[L]
	var zeroL L
	wordCount := len(zeroL)
	if modulus == nil || modulus.Sign() <= 0 || modulus.Bit(0) == 0 || modulus.BitLen() > wordCount*64 {
		return domain, false
	}
	domain.modulus = fixedLimbsFromBig[L](modulus)
	domain.modulusBig.Set(modulus)
	domain.pseudo256 = wordCount == 4 && modulus.Cmp(pseudoMersenne256Prime) == 0
	domain.archMul = fixedMulArchAvailable()

	// Newton iteration computes modulus[0]^-1 modulo 2^64. Montgomery
	// reduction uses its negation.
	inverse := uint64(1)
	for range 6 {
		inverse *= 2 - domain.modulus[0]*inverse
	}
	domain.m0Inv = 0 - inverse

	if domain.pseudo256 {
		domain.one[0] = 1
		domain.r2[0] = 1
	} else {
		var r, rMod, r2 big.Int
		r.Lsh(big.NewInt(1), uint(wordCount*64))
		rMod.Mod(&r, modulus)
		r2.Mul(&rMod, &rMod)
		r2.Mod(&r2, modulus)
		domain.one = fixedLimbsFromBig[L](&rMod)
		domain.r2 = fixedLimbsFromBig[L](&r2)
	}
	var exponent big.Int
	exponent.Sub(modulus, bigInt2)
	domain.minus2 = fixedLimbsFromBig[L](&exponent)
	return domain, true
}

func fixedLimbsFromBig[L fixedLimbs](value *big.Int) (out L) {
	var encoded [64]byte
	size := len(out) * 8
	value.FillBytes(encoded[len(encoded)-size:])
	for index := range len(out) {
		hi := len(encoded) - index*8
		out[index] = binary.BigEndian.Uint64(encoded[hi-8 : hi])
	}
	return out
}

func fixedLimbsToBig[L fixedLimbs](value L) *big.Int {
	var encoded [64]byte
	size := len(value) * 8
	for index := range len(value) {
		hi := len(encoded) - index*8
		binary.BigEndian.PutUint64(encoded[hi-8:hi], value[index])
	}
	return new(big.Int).SetBytes(encoded[len(encoded)-size:])
}

func (domain *montDomain[L]) normalFromBig(value *big.Int) L {
	if value.Sign() >= 0 && value.Cmp(&domain.modulusBig) < 0 {
		return fixedLimbsFromBig[L](value)
	}
	var reduced big.Int
	reduced.Mod(value, &domain.modulusBig)
	if reduced.Sign() < 0 {
		reduced.Add(&reduced, &domain.modulusBig)
	}
	return fixedLimbsFromBig[L](&reduced)
}

func (domain *montDomain[L]) normal(value L) L {
	if domain.pseudo256 {
		return value
	}
	var ordinaryOne L
	ordinaryOne[0] = 1
	return domain.montMul(value, ordinaryOne)
}

// fromBytes reduces a big-endian integer with a fixed double-and-add trace.
// It is used for private signing material and does not allocate a big.Int.
func (domain *montDomain[L]) fromBytes(encoded []byte) L {
	var result L
	for _, octet := range encoded {
		for bit := 7; bit >= 0; bit-- {
			result = domain.double(result)
			withOne := domain.add(result, domain.one)
			mask := uint64(0) - uint64((octet>>uint(bit))&1)
			result = fixedSelect(mask, withOne, result)
		}
	}
	return result
}

func (domain *montDomain[L]) fromNormalLimbs(value L) L {
	var result L
	for word := len(value); word > 0; {
		word--
		for bit := 64; bit > 0; {
			bit--
			result = domain.double(result)
			withOne := domain.add(result, domain.one)
			mask := uint64(0) - ((value[word] >> uint(bit)) & 1)
			result = fixedSelect(mask, withOne, result)
		}
	}
	return result
}

func fixedPutBigEndian[L fixedLimbs](dst []byte, value L) {
	for i := range len(value) {
		hi := len(dst) - i*8
		binary.BigEndian.PutUint64(dst[hi-8:hi], value[i])
	}
}

func (domain *montDomain[L]) fromBig(value *big.Int) L {
	normal := domain.normalFromBig(value)
	return domain.montMul(normal, domain.r2)
}

func (domain *montDomain[L]) toBig(value L) *big.Int {
	var ordinaryOne L
	ordinaryOne[0] = 1
	return fixedLimbsToBig(domain.montMul(value, ordinaryOne))
}

func (domain *montDomain[L]) montMul(x, y L) (out L) {
	if domain.pseudo256 { // public, immutable domain dispatch
		return domain.pseudoMersenneMul(x, y)
	}
	wordCount := len(out)
	// The largest supported domain has eight words. The extra word retains
	// carry during REDC.
	var product [17]uint64
	if domain.archMul {
		for i := 0; i < wordCount; i++ {
			product[i+wordCount] = fixedAddMulArch(&product[i], &x[0], y[i], wordCount)
		}
	} else {
		for i := 0; i < wordCount; i++ {
			carry := uint64(0)
			for j := 0; j < wordCount; j++ {
				hi, lo := bits.Mul64(x[j], y[i])
				var c uint64
				lo, c = bits.Add64(lo, product[i+j], 0)
				hi, _ = bits.Add64(hi, 0, c)
				lo, c = bits.Add64(lo, carry, 0)
				hi, _ = bits.Add64(hi, 0, c)
				product[i+j] = lo
				carry = hi
			}
			product[i+wordCount] = carry
		}
	}

	for i := 0; i < wordCount; i++ {
		factor := product[i] * domain.m0Inv
		carry := uint64(0)
		if domain.archMul {
			carry = fixedAddMulArch(&product[i], &domain.modulus[0], factor, wordCount)
		} else {
			for j := 0; j < wordCount; j++ {
				hi, lo := bits.Mul64(factor, domain.modulus[j])
				var c uint64
				lo, c = bits.Add64(lo, product[i+j], 0)
				hi, _ = bits.Add64(hi, 0, c)
				lo, c = bits.Add64(lo, carry, 0)
				hi, _ = bits.Add64(hi, 0, c)
				product[i+j] = lo
				carry = hi
			}
		}
		position := i + wordCount
		var propagation uint64
		product[position], propagation = bits.Add64(product[position], carry, 0)
		for position++; position <= 2*wordCount; position++ {
			product[position], propagation = bits.Add64(product[position], 0, propagation)
		}
	}

	var reduced L
	borrow := uint64(0)
	for i := 0; i < wordCount; i++ {
		out[i] = product[wordCount+i]
		reduced[i], borrow = bits.Sub64(out[i], domain.modulus[i], borrow)
	}
	_, borrow = bits.Sub64(product[2*wordCount], 0, borrow)
	useReduced := uint64(0) - (borrow ^ 1)
	return fixedSelect(useReduced, reduced, out)
}

// pseudoMersenneMul reduces a 512-bit product with 2^256 == 617 (mod P).
// The fixed carry folds cover the maximum intermediate and avoid division or
// data-dependent normalization.
func (domain *montDomain[L]) pseudoMersenneMul(x, y L) (out L) {
	var product [8]uint64
	if domain.archMul {
		for i := 0; i < 4; i++ {
			product[i+4] = fixedAddMulArch(&product[i], &x[0], y[i], 4)
		}
	} else {
		for i := 0; i < 4; i++ {
			carry := uint64(0)
			for j := 0; j < 4; j++ {
				hi, lo := bits.Mul64(x[j], y[i])
				var c uint64
				lo, c = bits.Add64(lo, product[i+j], 0)
				hi, _ = bits.Add64(hi, 0, c)
				lo, c = bits.Add64(lo, carry, 0)
				hi, _ = bits.Add64(hi, 0, c)
				product[i+j] = lo
				carry = hi
			}
			product[i+4] = carry
		}
	}

	carry := uint64(0)
	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(product[i+4], 617)
		var c uint64
		lo, c = bits.Add64(lo, product[i], 0)
		hi, _ = bits.Add64(hi, 0, c)
		lo, c = bits.Add64(lo, carry, 0)
		hi, _ = bits.Add64(hi, 0, c)
		out[i] = lo
		carry = hi
	}

	for range 2 {
		hi, lo := bits.Mul64(carry, 617)
		var c uint64
		out[0], c = bits.Add64(out[0], lo, 0)
		carry = hi + c
		for i := 1; i < 4; i++ {
			out[i], carry = bits.Add64(out[i], 0, carry)
		}
	}

	var reduced L
	borrow := uint64(0)
	for i := 0; i < 4; i++ {
		reduced[i], borrow = bits.Sub64(out[i], domain.modulus[i], borrow)
	}
	useReduced := uint64(0) - (borrow ^ 1)
	return fixedSelect(useReduced, reduced, out)
}

func (domain *montDomain[L]) add(x, y L) (sum L) {
	fixedTraceFieldAdd()
	carry := uint64(0)
	for i := range len(sum) {
		sum[i], carry = bits.Add64(x[i], y[i], carry)
	}
	var reduced L
	borrow := uint64(0)
	for i := range len(reduced) {
		reduced[i], borrow = bits.Sub64(sum[i], domain.modulus[i], borrow)
	}
	useReduced := uint64(0) - (carry | (borrow ^ 1))
	return fixedSelect(useReduced, reduced, sum)
}

func (domain *montDomain[L]) sub(x, y L) (difference L) {
	fixedTraceFieldSub()
	borrow := uint64(0)
	for i := range len(difference) {
		difference[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	mask := uint64(0) - borrow
	carry := uint64(0)
	for i := range len(difference) {
		difference[i], carry = bits.Add64(difference[i], domain.modulus[i]&mask, carry)
	}
	return difference
}

func (domain *montDomain[L]) double(x L) L { return domain.add(x, x) }
func (domain *montDomain[L]) mul(x, y L) L {
	fixedTraceFieldMul()
	return domain.montMul(x, y)
}
func (domain *montDomain[L]) square(x L) L {
	fixedTraceFieldSquare()
	return domain.montMul(x, x)
}

func (domain *montDomain[L]) neg(x L) L {
	var zero L
	return domain.sub(zero, x)
}

func (domain *montDomain[L]) invert(x L) L {
	fixedTraceFieldInvert()
	result := domain.one
	for bit := len(domain.minus2)*64 - 1; bit >= 0; bit-- {
		result = domain.square(result)
		multiplied := domain.mul(result, x)
		mask := uint64(0) - ((domain.minus2[bit/64] >> uint(bit%64)) & 1)
		result = fixedSelect(mask, multiplied, result)
	}
	return result
}

func fixedSelect[L fixedLimbs](mask uint64, yes, no L) (out L) {
	for i := range len(out) {
		out[i] = (yes[i] & mask) | (no[i] &^ mask)
	}
	return out
}

func fixedZeroMask[L fixedLimbs](value L) uint64 {
	combined := uint64(0)
	for i := range len(value) {
		combined |= value[i]
	}
	nonZero := (combined | (0 - combined)) >> 63
	return uint64(0) - (nonZero ^ 1)
}

func fixedEqualMask[L fixedLimbs](x, y L) uint64 {
	combined := uint64(0)
	for i := range len(x) {
		combined |= x[i] ^ y[i]
	}
	nonEqual := (combined | (0 - combined)) >> 63
	return uint64(0) - (nonEqual ^ 1)
}

func fixedWordEqualMask(x, y uint64) uint64 {
	difference := x ^ y
	nonEqual := (difference | (0 - difference)) >> 63
	return uint64(0) - (nonEqual ^ 1)
}

type fixedPoint[L fixedLimbs] struct {
	x, y, z L
}

type fixedAffine[L fixedLimbs] struct {
	x, y L
}

// fixedProjective uses homogeneous coordinates x=X/Z, y=Y/Z. It is kept
// separate from fixedPoint (Jacobian coordinates) so the complete RCB mixed
// addition formulas can be used by the fixed-base comb without conversions.
type fixedProjective[L fixedLimbs] struct {
	x, y, z L
}

type fixedEdwardsPoint[L fixedLimbs] struct {
	x, y, t, z L
}

type fixedEdwardsAffine[L fixedLimbs] struct {
	x, y, t L
}

type fixedCurve[L fixedLimbs] struct {
	p, q        montDomain[L]
	a, b, b3    L
	base        fixedPoint[L]
	cofactor    *big.Int
	aMinus3     bool
	edwards     bool
	edE         L
	edEOne      bool
	edD         L
	edS         L
	edT         L
	edBase      fixedEdwardsPoint[L]
	orderNAF    [513]int8
	orderNAFLen int

	baseOnce       sync.Once
	baseTable      [][16]fixedAffine[L]
	edBaseTable    [][16]fixedEdwardsAffine[L]
	verifyBaseOnce sync.Once
	verifyBase     [8]fixedPoint[L]
	edVerifyOnce   sync.Once
	edVerifyBase   [8]fixedEdwardsPoint[L]
}

func newFixedCurve[L fixedLimbs](domain *curveDomain) (*fixedCurve[L], bool) {
	p, ok := newMontDomain[L](&domain.p)
	if !ok {
		return nil, false
	}
	q, ok := newMontDomain[L](&domain.q)
	if !ok {
		return nil, false
	}
	curve := &fixedCurve[L]{
		p:        p,
		q:        q,
		a:        p.fromBig(&domain.a),
		b:        p.fromBig(&domain.b),
		cofactor: new(big.Int).Set(&domain.co),
	}
	var pMinus3 big.Int
	pMinus3.Sub(&domain.p, bigInt3)
	curve.aMinus3 = domain.a.Cmp(&pMinus3) == 0
	curve.b3 = p.add(curve.b, p.double(curve.b))
	curve.base = curve.pointFromBig(&domain.x, &domain.y)
	if domain.hasE && domain.hasD {
		curve.edE = p.fromBig(&domain.e)
		curve.edEOne = domain.e.Cmp(bigInt1) == 0
		curve.edD = p.fromBig(&domain.d)
		fourInverse := p.invert(p.fromBig(bigInt4))
		curve.edS = p.mul(p.sub(curve.edE, curve.edD), fourInverse)
		var six big.Int
		six.SetUint64(6)
		sixInverse := p.invert(p.fromBig(&six))
		curve.edT = p.mul(p.add(curve.edE, curve.edD), sixInverse)
		curve.edwards = true
		curve.edBase = curve.edwardsFromWeierstrass(p.fromBig(&domain.x), p.fromBig(&domain.y))
		if domain.co.Cmp(bigInt1) != 0 {
			curve.orderNAFLen = width5NAF(&domain.q, &curve.orderNAF)
		}
	}
	return curve, true
}

func fixedSelectProjective[L fixedLimbs](mask uint64, yes, no fixedProjective[L]) fixedProjective[L] {
	return fixedProjective[L]{
		x: fixedSelect(mask, yes.x, no.x),
		y: fixedSelect(mask, yes.y, no.y),
		z: fixedSelect(mask, yes.z, no.z),
	}
}

func (curve *fixedCurve[L]) projectiveInfinity() fixedProjective[L] {
	return fixedProjective[L]{y: curve.p.one}
}

func (curve *fixedCurve[L]) mulA(value L) L {
	if curve.aMinus3 { // public, immutable domain property
		return curve.p.neg(curve.p.add(curve.p.double(value), value))
	}
	return curve.p.mul(curve.a, value)
}

// projectiveAddMixedComplete implements Algorithm 2 / madd-2015-rcb from
// Renes-Costello-Batina. right must be affine and non-infinite; rightInfinity
// masks the result back to left after running the same field-operation trace.
func (curve *fixedCurve[L]) projectiveAddMixedComplete(left fixedProjective[L], right fixedAffine[L], rightInfinity uint64) fixedProjective[L] {
	fixedTraceProjectiveAdd()
	p := &curve.p
	t0 := p.mul(left.x, right.x)
	t1 := p.mul(left.y, right.y)
	t3 := p.mul(p.add(right.x, right.y), p.add(left.x, left.y))
	t3 = p.sub(t3, p.add(t0, t1))
	t4 := p.add(p.mul(right.x, left.z), left.x)
	t5 := p.add(p.mul(right.y, left.z), left.y)
	z3 := curve.mulA(t4)
	x3 := p.mul(curve.b3, left.z)
	z3 = p.add(x3, z3)
	x3 = p.sub(t1, z3)
	z3 = p.add(t1, z3)
	y3 := p.mul(x3, z3)
	t1 = p.add(p.double(t0), t0)
	t2 := curve.mulA(left.z)
	t4 = p.mul(curve.b3, t4)
	t1 = p.add(t1, t2)
	t2 = curve.mulA(p.sub(t0, t2))
	t4 = p.add(t4, t2)
	t0 = p.mul(t1, t4)
	y3 = p.add(y3, t0)
	t0 = p.mul(t5, t4)
	x3 = p.sub(p.mul(t3, x3), t0)
	t0 = p.mul(t3, t1)
	z3 = p.add(p.mul(t5, z3), t0)
	result := fixedProjective[L]{x: x3, y: y3, z: z3}
	return fixedSelectProjective(rightInfinity, left, result)
}

func (curve *fixedCurve[L]) edwardsIdentity() fixedEdwardsPoint[L] {
	return fixedEdwardsPoint[L]{y: curve.p.one, z: curve.p.one}
}

func fixedSelectEdwards[L fixedLimbs](mask uint64, yes, no fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	return fixedEdwardsPoint[L]{
		x: fixedSelect(mask, yes.x, no.x),
		y: fixedSelect(mask, yes.y, no.y),
		t: fixedSelect(mask, yes.t, no.t),
		z: fixedSelect(mask, yes.z, no.z),
	}
}

func (curve *fixedCurve[L]) edwardsFromWeierstrass(x, y L) fixedEdwardsPoint[L] {
	// u=(x-t)/y and v=(x-t-s)/(x-t+s), represented without an
	// inversion by the common denominator y*(x-t+s).
	a := curve.p.sub(x, curve.edT)
	aPlusS := curve.p.add(a, curve.edS)
	aMinusS := curve.p.sub(a, curve.edS)
	return fixedEdwardsPoint[L]{
		x: curve.p.mul(a, aPlusS),
		y: curve.p.mul(y, aMinusS),
		t: curve.p.mul(a, aMinusS),
		z: curve.p.mul(y, aPlusS),
	}
}

func (curve *fixedCurve[L]) edwardsAdd(left, right fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	fixedTraceEdwardsAdd()
	p := &curve.p
	a := p.mul(left.x, right.x)
	b := p.mul(left.y, right.y)
	c := p.mul(curve.edD, p.mul(left.t, right.t))
	d := p.mul(left.z, right.z)
	e := p.mul(p.add(left.x, left.y), p.add(right.x, right.y))
	e = p.sub(p.sub(e, a), b)
	f := p.sub(d, c)
	g := p.add(d, c)
	h := p.sub(b, a)
	if !curve.edEOne {
		h = p.sub(b, p.mul(curve.edE, a))
	}
	return fixedEdwardsPoint[L]{
		x: p.mul(e, f),
		y: p.mul(g, h),
		t: p.mul(e, h),
		z: p.mul(f, g),
	}
}

// edwardsAddMixed uses the complete extended-Edwards addition law with an
// affine right operand. rightIdentity masks a zero comb digit back to left,
// while the arithmetic trace remains identical for every digit.
func (curve *fixedCurve[L]) edwardsAddMixed(left fixedEdwardsPoint[L], right fixedEdwardsAffine[L], rightIdentity uint64) fixedEdwardsPoint[L] {
	fixedTraceEdwardsAdd()
	p := &curve.p
	a := p.mul(left.x, right.x)
	b := p.mul(left.y, right.y)
	c := p.mul(curve.edD, p.mul(left.t, right.t))
	d := left.z
	e := p.mul(p.add(left.x, left.y), p.add(right.x, right.y))
	e = p.sub(p.sub(e, a), b)
	f := p.sub(d, c)
	g := p.add(d, c)
	h := p.sub(b, a)
	if !curve.edEOne {
		h = p.sub(b, p.mul(curve.edE, a))
	}
	result := fixedEdwardsPoint[L]{
		x: p.mul(e, f),
		y: p.mul(g, h),
		t: p.mul(e, h),
		z: p.mul(f, g),
	}
	return fixedSelectEdwards(rightIdentity, left, result)
}

func (curve *fixedCurve[L]) edwardsDouble(point fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	fixedTraceEdwardsDouble()
	p := &curve.p
	a := p.square(point.x)
	b := p.square(point.y)
	c := p.double(p.square(point.z))
	d := a
	if !curve.edEOne {
		d = p.mul(curve.edE, a)
	}
	e := p.square(p.add(point.x, point.y))
	e = p.sub(p.sub(e, a), b)
	g := p.add(d, b)
	f := p.sub(g, c)
	h := p.sub(d, b)
	return fixedEdwardsPoint[L]{
		x: p.mul(e, f),
		y: p.mul(g, h),
		t: p.mul(e, h),
		z: p.mul(f, g),
	}
}

func (curve *fixedCurve[L]) selectEdwards(table *[16]fixedEdwardsPoint[L], index uint64) fixedEdwardsPoint[L] {
	result := curve.edwardsIdentity()
	for candidate := uint64(0); candidate < 16; candidate++ {
		result = fixedSelectEdwards(fixedWordEqualMask(index, candidate), table[candidate], result)
	}
	return result
}

func (curve *fixedCurve[L]) edwardsMultiply(point fixedEdwardsPoint[L], scalar L) fixedEdwardsPoint[L] {
	var table [16]fixedEdwardsPoint[L]
	table[0] = curve.edwardsIdentity()
	table[1] = point
	for i := 2; i < len(table); i++ {
		table[i] = curve.edwardsAdd(table[i-1], point)
	}
	result := curve.edwardsIdentity()
	for window := len(scalar) * 16; window > 0; {
		window--
		for range 4 {
			result = curve.edwardsDouble(result)
		}
		result = curve.edwardsAdd(result, curve.selectEdwards(&table, fixedScalarNibble(scalar, window)))
	}
	return result
}

func (curve *fixedCurve[L]) edwardsMultiplySmall(point fixedEdwardsPoint[L], scalar *big.Int) fixedEdwardsPoint[L] {
	result := curve.edwardsIdentity()
	for bit := scalar.BitLen(); bit > 0; {
		bit--
		result = curve.edwardsDouble(result)
		if scalar.Bit(bit) != 0 { // public cofactor
			result = curve.edwardsAdd(result, point)
		}
	}
	return result
}

// The subgroup check only inspects X, Y and Z of [Q]P. A doubling ignores
// the input T coordinate, so an addition need not produce it; a doubling
// only produces T when the next operation is an addition. Q's signed digits
// are precomputed once for the immutable curve domain.
func (curve *fixedCurve[L]) edwardsMultiplySubgroup(point fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	if curve.orderNAFLen == 0 {
		return fixedEdwardsPoint[L]{}
	}
	table := curve.edwardsOddMultiples(point)
	selectPoint := func(digit int8) fixedEdwardsPoint[L] {
		index := int(digit)
		if index < 0 {
			index = -index
		}
		selected := table[(index-1)/2]
		if digit < 0 {
			selected.x = curve.p.neg(selected.x)
			selected.t = curve.p.neg(selected.t)
		}
		return selected
	}
	result := selectPoint(curve.orderNAF[curve.orderNAFLen-1])
	for bit := curve.orderNAFLen - 1; bit > 0; {
		bit--
		digit := curve.orderNAF[bit]
		add := digit != 0
		result = curve.edwardsDoubleSubgroup(result, add)
		if add {
			result = curve.edwardsAddSubgroup(result, selectPoint(digit))
		}
	}
	return result
}

func (curve *fixedCurve[L]) edwardsDoubleSubgroup(point fixedEdwardsPoint[L], withT bool) fixedEdwardsPoint[L] {
	fixedTraceEdwardsDouble()
	p := &curve.p
	a := p.square(point.x)
	b := p.square(point.y)
	c := p.double(p.square(point.z))
	d := a
	if !curve.edEOne {
		d = p.mul(curve.edE, a)
	}
	e := p.square(p.add(point.x, point.y))
	e = p.sub(p.sub(e, a), b)
	g := p.add(d, b)
	f := p.sub(g, c)
	h := p.sub(d, b)
	result := fixedEdwardsPoint[L]{
		x: p.mul(e, f),
		y: p.mul(g, h),
		z: p.mul(f, g),
	}
	if withT {
		result.t = p.mul(e, h)
	}
	return result
}

func (curve *fixedCurve[L]) edwardsAddSubgroup(left, right fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	fixedTraceEdwardsAdd()
	p := &curve.p
	a := p.mul(left.x, right.x)
	b := p.mul(left.y, right.y)
	c := p.mul(curve.edD, p.mul(left.t, right.t))
	d := p.mul(left.z, right.z)
	e := p.mul(p.add(left.x, left.y), p.add(right.x, right.y))
	e = p.sub(p.sub(e, a), b)
	f := p.sub(d, c)
	g := p.add(d, c)
	h := p.sub(b, a)
	if !curve.edEOne {
		h = p.sub(b, p.mul(curve.edE, a))
	}
	return fixedEdwardsPoint[L]{
		x: p.mul(e, f),
		y: p.mul(g, h),
		z: p.mul(f, g),
	}
}

func (curve *fixedCurve[L]) edwardsOddMultiples(point fixedEdwardsPoint[L]) [8]fixedEdwardsPoint[L] {
	var table [8]fixedEdwardsPoint[L]
	table[0] = point
	two := curve.edwardsDouble(point)
	for i := 1; i < len(table); i++ {
		table[i] = curve.edwardsAdd(table[i-1], two)
	}
	return table
}

func (curve *fixedCurve[L]) buildEdwardsVerifyBase() {
	curve.edVerifyBase = curve.edwardsOddMultiples(curve.edBase)
}

func (curve *fixedCurve[L]) edwardsAddSignedPublic(point fixedEdwardsPoint[L], table *[8]fixedEdwardsPoint[L], digit int8) fixedEdwardsPoint[L] {
	if digit == 0 {
		return point
	}
	index := int(digit)
	if index < 0 {
		index = -index
	}
	selected := table[(index-1)/2]
	if digit < 0 {
		selected.x = curve.p.neg(selected.x)
		selected.t = curve.p.neg(selected.t)
	}
	return curve.edwardsAdd(point, selected)
}

func (curve *fixedCurve[L]) edwardsDoublePublic(baseScalar, pointScalar *big.Int, point fixedEdwardsPoint[L]) fixedEdwardsPoint[L] {
	var baseDigits, pointDigits [513]int8
	baseLength := width5NAF(baseScalar, &baseDigits)
	pointLength := width5NAF(pointScalar, &pointDigits)
	length := baseLength
	if pointLength > length {
		length = pointLength
	}
	curve.edVerifyOnce.Do(curve.buildEdwardsVerifyBase)
	pointTable := curve.edwardsOddMultiples(point)
	result := curve.edwardsIdentity()
	for i := length; i > 0; {
		i--
		result = curve.edwardsDouble(result)
		result = curve.edwardsAddSignedPublic(result, &curve.edVerifyBase, baseDigits[i])
		result = curve.edwardsAddSignedPublic(result, &pointTable, pointDigits[i])
	}
	return result
}

func (curve *fixedCurve[L]) edwardsToWeierstrass(point fixedEdwardsPoint[L]) (x, y L, invalid uint64) {
	p := &curve.p
	zPlusY := p.add(point.z, point.y)
	zMinusY := p.sub(point.z, point.y)
	denominator := p.mul(point.x, zMinusY)
	inverse := p.invert(denominator)
	common := p.mul(curve.edS, zPlusY)
	x = p.add(p.mul(p.mul(common, point.x), inverse), curve.edT)
	y = p.mul(p.mul(common, point.z), inverse)
	invalid = fixedZeroMask(denominator)
	return x, y, invalid
}

func (curve *fixedCurve[L]) infinity() fixedPoint[L] {
	return fixedPoint[L]{y: curve.p.one}
}

func (curve *fixedCurve[L]) pointFromBig(x, y *big.Int) fixedPoint[L] {
	return fixedPoint[L]{x: curve.p.fromBig(x), y: curve.p.fromBig(y), z: curve.p.one}
}

func (curve *fixedCurve[L]) contains(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(&curve.p.modulusBig) >= 0 || y.Cmp(&curve.p.modulusBig) >= 0 {
		return false
	}
	fx := curve.p.fromBig(x)
	fy := curve.p.fromBig(y)
	left := curve.p.square(fy)
	right := curve.p.add(curve.p.add(curve.p.mul(curve.p.square(fx), fx), curve.p.mul(curve.a, fx)), curve.b)
	return fixedEqualMask(left, right) != 0
}

func fixedSelectPoint[L fixedLimbs](mask uint64, yes, no fixedPoint[L]) fixedPoint[L] {
	return fixedPoint[L]{
		x: fixedSelect(mask, yes.x, no.x),
		y: fixedSelect(mask, yes.y, no.y),
		z: fixedSelect(mask, yes.z, no.z),
	}
}

func (curve *fixedCurve[L]) pointDouble(point fixedPoint[L]) fixedPoint[L] {
	fixedTracePointDouble()
	p := &curve.p
	xx := p.square(point.x)
	yy := p.square(point.y)
	yyyy := p.square(yy)
	zz := p.square(point.z)
	tmp := p.add(point.x, yy)
	tmp = p.square(tmp)
	tmp = p.sub(tmp, xx)
	tmp = p.sub(tmp, yyyy)
	s := p.double(tmp)
	m := p.add(p.double(xx), xx)
	zz4 := p.square(zz)
	m = p.add(m, curve.mulA(zz4))
	x3 := p.square(m)
	x3 = p.sub(x3, p.double(s))
	y3 := p.mul(p.sub(s, x3), m)
	eightYYYY := p.double(p.double(p.double(yyyy)))
	y3 = p.sub(y3, eightYYYY)
	z3 := p.double(p.mul(point.y, point.z))
	result := fixedPoint[L]{x: x3, y: y3, z: z3}
	invalid := fixedZeroMask(point.z) | fixedZeroMask(point.y)
	return fixedSelectPoint(invalid, curve.infinity(), result)
}

func (curve *fixedCurve[L]) pointAdd(left, right fixedPoint[L]) fixedPoint[L] {
	fixedTracePointAdd()
	p := &curve.p
	z1z1 := p.square(left.z)
	z2z2 := p.square(right.z)
	u1 := p.mul(left.x, z2z2)
	u2 := p.mul(right.x, z1z1)
	s1 := p.mul(left.y, p.mul(right.z, z2z2))
	s2 := p.mul(right.y, p.mul(left.z, z1z1))
	h := p.sub(u2, u1)
	sDifference := p.sub(s2, s1)
	i := p.square(p.double(h))
	j := p.mul(h, i)
	r := p.double(sDifference)
	v := p.mul(u1, i)
	x3 := p.square(r)
	x3 = p.sub(p.sub(x3, j), p.double(v))
	y3 := p.mul(p.sub(v, x3), r)
	y3 = p.sub(y3, p.double(p.mul(s1, j)))
	z3 := p.add(left.z, right.z)
	z3 = p.square(z3)
	z3 = p.sub(p.sub(z3, z1z1), z2z2)
	z3 = p.mul(z3, h)
	result := fixedPoint[L]{x: x3, y: y3, z: z3}

	leftInfinity := fixedZeroMask(left.z)
	rightInfinity := fixedZeroMask(right.z)
	hZero := fixedZeroMask(h)
	sameY := fixedZeroMask(sDifference)
	samePoint := hZero & sameY
	oppositePoint := hZero &^ sameY
	result = fixedSelectPoint(oppositePoint, curve.infinity(), result)
	result = fixedSelectPoint(samePoint, curve.pointDouble(left), result)
	result = fixedSelectPoint(rightInfinity, left, result)
	result = fixedSelectPoint(leftInfinity, right, result)
	return result
}

func (curve *fixedCurve[L]) scalarFromBig(value *big.Int) L {
	return curve.q.normalFromBig(value)
}

func fixedScalarNibble[L fixedLimbs](scalar L, window int) uint64 {
	return (scalar[window/16] >> uint((window%16)*4)) & 15
}

func (curve *fixedCurve[L]) selectPoint(table *[16]fixedPoint[L], index uint64) fixedPoint[L] {
	result := curve.infinity()
	for candidate := uint64(0); candidate < 16; candidate++ {
		result = fixedSelectPoint(fixedWordEqualMask(index, candidate), table[candidate], result)
	}
	return result
}

func (curve *fixedCurve[L]) multiply(point fixedPoint[L], scalar L) fixedPoint[L] {
	var table [16]fixedPoint[L]
	table[0] = curve.infinity()
	table[1] = point
	for i := 2; i < len(table); i++ {
		table[i] = curve.pointAdd(table[i-1], point)
	}
	result := curve.infinity()
	windows := len(scalar) * 16
	for window := windows; window > 0; {
		window--
		for range 4 {
			result = curve.pointDouble(result)
		}
		selected := curve.selectPoint(&table, fixedScalarNibble(scalar, window))
		result = curve.pointAdd(result, selected)
	}
	return result
}

func (curve *fixedCurve[L]) multiplySmall(point fixedPoint[L], scalar *big.Int) fixedPoint[L] {
	result := curve.infinity()
	for bit := scalar.BitLen(); bit > 0; {
		bit--
		result = curve.pointDouble(result)
		if scalar.Bit(bit) != 0 { // scalar is a public domain parameter
			result = curve.pointAdd(result, point)
		}
	}
	return result
}

// width5NAF converts a public scalar to a width-five non-adjacent form. It is
// deliberately variable-time: signature verification and subgroup checks use
// only public scalars here.
func width5NAF(scalar *big.Int, digits *[513]int8) int {
	var value big.Int
	var adjustment big.Int
	value.Set(scalar)
	length := 0
	for value.Sign() != 0 {
		if value.Bit(0) != 0 {
			digit := int64(value.Uint64() & 31)
			if digit > 16 {
				digit -= 32
			}
			digits[length] = int8(digit)
			if digit > 0 {
				adjustment.SetInt64(digit)
				value.Sub(&value, &adjustment)
			} else {
				adjustment.SetInt64(-digit)
				value.Add(&value, &adjustment)
			}
		}
		value.Rsh(&value, 1)
		length++
	}
	return length
}

func (curve *fixedCurve[L]) oddMultiples(point fixedPoint[L]) [8]fixedPoint[L] {
	var table [8]fixedPoint[L]
	table[0] = point
	two := curve.pointDouble(point)
	for i := 1; i < len(table); i++ {
		table[i] = curve.pointAdd(table[i-1], two)
	}
	return table
}

func (curve *fixedCurve[L]) buildVerifyBase() {
	curve.verifyBase = curve.oddMultiples(curve.base)
}

func (curve *fixedCurve[L]) addSignedPublic(point fixedPoint[L], table *[8]fixedPoint[L], digit int8) fixedPoint[L] {
	if digit == 0 {
		return point
	}
	index := int(digit)
	if index < 0 {
		index = -index
	}
	selected := table[(index-1)/2]
	if digit < 0 {
		selected.y = curve.p.neg(selected.y)
	}
	return curve.pointAdd(point, selected)
}

// multiplyDoublePublic uses Straus wNAF(5). Its branches and table indexes
// depend on public signature values only, which makes it faster than applying
// the constant-time arbitrary-point multiplier twice during verification.
func (curve *fixedCurve[L]) multiplyDoublePublic(baseScalar, pointScalar *big.Int, point fixedPoint[L]) fixedPoint[L] {
	var baseDigits, pointDigits [513]int8
	baseLength := width5NAF(baseScalar, &baseDigits)
	pointLength := width5NAF(pointScalar, &pointDigits)
	length := baseLength
	if pointLength > length {
		length = pointLength
	}
	curve.verifyBaseOnce.Do(curve.buildVerifyBase)
	pointTable := curve.oddMultiples(point)
	result := curve.infinity()
	for i := length; i > 0; {
		i--
		result = curve.pointDouble(result)
		result = curve.addSignedPublic(result, &curve.verifyBase, baseDigits[i])
		result = curve.addSignedPublic(result, &pointTable, pointDigits[i])
	}
	return result
}

func (curve *fixedCurve[L]) buildBaseTable() {
	if curve.edwards {
		curve.buildEdwardsBaseTable()
		return
	}
	windows := len(curve.p.modulus) * 16
	projective := make([]fixedPoint[L], windows*15)
	current := curve.base
	for window := 0; window < windows; window++ {
		projective[window*15] = current
		for digit := 2; digit < 16; digit++ {
			projective[window*15+digit-1] = curve.pointAdd(projective[window*15+digit-2], current)
		}
		for range 4 {
			current = curve.pointDouble(current)
		}
	}

	// Montgomery batch inversion converts every non-zero Z coordinate with a
	// single field inversion. The temporary projective table is released after
	// the immutable packed affine table has been installed.
	prefix := make([]L, len(projective))
	accumulator := curve.p.one
	for i := range projective {
		prefix[i] = accumulator
		accumulator = curve.p.mul(accumulator, projective[i].z)
	}
	inverse := curve.p.invert(accumulator)
	curve.baseTable = make([][16]fixedAffine[L], windows)
	for i := len(projective); i > 0; {
		i--
		inverseZ := curve.p.mul(inverse, prefix[i])
		inverse = curve.p.mul(inverse, projective[i].z)
		inverseZ2 := curve.p.square(inverseZ)
		inverseZ3 := curve.p.mul(inverseZ2, inverseZ)
		window := i / 15
		digit := i%15 + 1
		curve.baseTable[window][digit] = fixedAffine[L]{
			x: curve.p.mul(projective[i].x, inverseZ2),
			y: curve.p.mul(projective[i].y, inverseZ3),
		}
	}
}

func (curve *fixedCurve[L]) buildEdwardsBaseTable() {
	windows := len(curve.p.modulus) * 16
	projective := make([]fixedEdwardsPoint[L], windows*15)
	current := curve.edBase
	for window := 0; window < windows; window++ {
		projective[window*15] = current
		for digit := 2; digit < 16; digit++ {
			projective[window*15+digit-1] = curve.edwardsAdd(projective[window*15+digit-2], current)
		}
		for range 4 {
			current = curve.edwardsDouble(current)
		}
	}

	// Three packed affine coordinates make the table exactly 96 KiB for a
	// 256-bit domain and 384 KiB for a 512-bit domain. One batch inversion
	// normalizes every extended point.
	prefix := make([]L, len(projective))
	accumulator := curve.p.one
	for i := range projective {
		prefix[i] = accumulator
		accumulator = curve.p.mul(accumulator, projective[i].z)
	}
	inverse := curve.p.invert(accumulator)
	curve.edBaseTable = make([][16]fixedEdwardsAffine[L], windows)
	for i := len(projective); i > 0; {
		i--
		inverseZ := curve.p.mul(inverse, prefix[i])
		inverse = curve.p.mul(inverse, projective[i].z)
		window := i / 15
		digit := i%15 + 1
		curve.edBaseTable[window][digit] = fixedEdwardsAffine[L]{
			x: curve.p.mul(projective[i].x, inverseZ),
			y: curve.p.mul(projective[i].y, inverseZ),
			t: curve.p.mul(projective[i].t, inverseZ),
		}
	}
}

func (curve *fixedCurve[L]) multiplyBaseEdwards(scalar L) fixedEdwardsPoint[L] {
	curve.baseOnce.Do(curve.buildBaseTable)
	result := curve.edwardsIdentity()
	for window := range len(curve.edBaseTable) {
		index := fixedScalarNibble(scalar, window)
		// Element zero is deliberately represented by an arbitrary valid point;
		// rightIdentity masks it away after the complete addition formula.
		affine := curve.edBaseTable[window][1]
		for candidate := uint64(1); candidate < 16; candidate++ {
			mask := fixedWordEqualMask(index, candidate)
			affine.x = fixedSelect(mask, curve.edBaseTable[window][candidate].x, affine.x)
			affine.y = fixedSelect(mask, curve.edBaseTable[window][candidate].y, affine.y)
			affine.t = fixedSelect(mask, curve.edBaseTable[window][candidate].t, affine.t)
		}
		result = curve.edwardsAddMixed(result, affine, fixedWordEqualMask(index, 0))
	}
	return result
}

func (curve *fixedCurve[L]) multiplyBase(scalar L) fixedPoint[L] {
	curve.baseOnce.Do(curve.buildBaseTable)
	result := curve.infinity()
	for window := range len(curve.baseTable) {
		index := fixedScalarNibble(scalar, window)
		var affine fixedAffine[L]
		for candidate := uint64(0); candidate < 16; candidate++ {
			mask := fixedWordEqualMask(index, candidate)
			affine.x = fixedSelect(mask, curve.baseTable[window][candidate].x, affine.x)
			affine.y = fixedSelect(mask, curve.baseTable[window][candidate].y, affine.y)
		}
		nonZero := ^fixedWordEqualMask(index, 0)
		var zero L
		selected := fixedPoint[L]{
			x: affine.x,
			y: fixedSelect(nonZero, affine.y, curve.p.one),
			z: fixedSelect(nonZero, curve.p.one, zero),
		}
		result = curve.pointAdd(result, selected)
	}
	return result
}

func (curve *fixedCurve[L]) multiplyBaseProjective(scalar L) fixedProjective[L] {
	curve.baseOnce.Do(curve.buildBaseTable)
	result := curve.projectiveInfinity()
	for window := range len(curve.baseTable) {
		index := fixedScalarNibble(scalar, window)
		// Element zero is an arbitrary valid affine point for purposes of the
		// formula; the final mask discards it when this scalar window is zero.
		affine := curve.baseTable[window][1]
		for candidate := uint64(1); candidate < 16; candidate++ {
			mask := fixedWordEqualMask(index, candidate)
			affine.x = fixedSelect(mask, curve.baseTable[window][candidate].x, affine.x)
			affine.y = fixedSelect(mask, curve.baseTable[window][candidate].y, affine.y)
		}
		result = curve.projectiveAddMixedComplete(result, affine, fixedWordEqualMask(index, 0))
	}
	return result
}

func (curve *fixedCurve[L]) affine(point fixedPoint[L]) (*big.Int, *big.Int, error) {
	if fixedZeroMask(point.z) != 0 {
		return nil, nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	inverseZ := curve.p.invert(point.z)
	inverseZ2 := curve.p.square(inverseZ)
	inverseZ3 := curve.p.mul(inverseZ2, inverseZ)
	x := curve.p.mul(point.x, inverseZ2)
	y := curve.p.mul(point.y, inverseZ3)
	return curve.p.toBig(x), curve.p.toBig(y), nil
}

func (curve *fixedCurve[L]) affineRawLE(point fixedPoint[L]) ([]byte, error) {
	if fixedZeroMask(point.z) != 0 {
		return nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	inverseZ := curve.p.invert(point.z)
	inverseZ2 := curve.p.square(inverseZ)
	inverseZ3 := curve.p.mul(inverseZ2, inverseZ)
	x := curve.p.normal(curve.p.mul(point.x, inverseZ2))
	y := curve.p.normal(curve.p.mul(point.y, inverseZ3))
	pointSize := len(x) * 8
	raw := make([]byte, 2*pointSize)
	for i := range len(x) {
		binary.LittleEndian.PutUint64(raw[i*8:i*8+8], x[i])
		binary.LittleEndian.PutUint64(raw[pointSize+i*8:pointSize+i*8+8], y[i])
	}
	return raw, nil
}

func (curve *fixedCurve[L]) projectiveAffine(point fixedProjective[L]) (*big.Int, *big.Int, error) {
	if fixedZeroMask(point.z) != 0 {
		return nil, nil, errors.New("gogost/gost3410: точка на бесконечности")
	}
	inverseZ := curve.p.invert(point.z)
	x := curve.p.mul(point.x, inverseZ)
	y := curve.p.mul(point.y, inverseZ)
	return curve.p.toBig(x), curve.p.toBig(y), nil
}

func (curve *fixedCurve[L]) projectiveX(point fixedProjective[L]) (L, uint64) {
	inverseZ := curve.p.invert(point.z)
	x := curve.p.mul(point.x, inverseZ)
	return curve.p.normal(x), fixedZeroMask(point.z)
}

func (curve *fixedCurve[L]) edwardsAffine(point fixedEdwardsPoint[L]) (*big.Int, *big.Int, error) {
	x, y, invalid := curve.edwardsToWeierstrass(point)
	if invalid != 0 {
		return nil, nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	return curve.p.toBig(x), curve.p.toBig(y), nil
}

func (curve *fixedCurve[L]) edwardsRawLE(point fixedEdwardsPoint[L]) ([]byte, error) {
	x, y, invalid := curve.edwardsToWeierstrass(point)
	if invalid != 0 {
		return nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	x = curve.p.normal(x)
	y = curve.p.normal(y)
	pointSize := len(x) * 8
	raw := make([]byte, 2*pointSize)
	for i := range len(x) {
		binary.LittleEndian.PutUint64(raw[i*8:i*8+8], x[i])
		binary.LittleEndian.PutUint64(raw[pointSize+i*8:pointSize+i*8+8], y[i])
	}
	return raw, nil
}

func (curve *fixedCurve[L]) edwardsX(point fixedEdwardsPoint[L]) (L, uint64) {
	x, _, invalid := curve.edwardsToWeierstrass(point)
	return curve.p.normal(x), invalid
}

func (curve *fixedCurve[L]) expBase(scalar *big.Int) (*big.Int, *big.Int, error) {
	if scalar.Sign() == 0 {
		return nil, nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	if curve.edwards {
		return curve.edwardsAffine(curve.multiplyBaseEdwards(curve.scalarFromBig(scalar)))
	}
	return curve.projectiveAffine(curve.multiplyBaseProjective(curve.scalarFromBig(scalar)))
}

func (curve *fixedCurve[L]) expPoint(scalar *big.Int, x, y *big.Int) (*big.Int, *big.Int, error) {
	if scalar.Sign() == 0 {
		return nil, nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	if curve.edwards {
		point := curve.edwardsFromWeierstrass(curve.p.fromBig(x), curve.p.fromBig(y))
		return curve.edwardsAffine(curve.edwardsMultiply(point, curve.scalarFromBig(scalar)))
	}
	return curve.affine(curve.multiply(curve.pointFromBig(x, y), curve.scalarFromBig(scalar)))
}

func (curve *fixedCurve[L]) expDoublePublic(baseScalar, pointScalar, x, y *big.Int) (*big.Int, *big.Int, error) {
	if baseScalar.Sign() == 0 && pointScalar.Sign() == 0 {
		return nil, nil, errors.New("gogost/gost3410: нулевая степень")
	}
	if curve.edwards {
		point := curve.edwardsFromWeierstrass(curve.p.fromBig(x), curve.p.fromBig(y))
		return curve.edwardsAffine(curve.edwardsDoublePublic(baseScalar, pointScalar, point))
	}
	point := curve.pointFromBig(x, y)
	return curve.affine(curve.multiplyDoublePublic(baseScalar, pointScalar, point))
}

func (curve *fixedCurve[L]) signDigest(private *big.Int, digest []byte, random io.Reader) ([]byte, error) {
	d := curve.q.fromBig(private)
	e := curve.q.fromBytes(digest)
	e = fixedSelect(fixedZeroMask(e), curve.q.one, e)
	pointSize := len(curve.q.modulus) * 8
	var randomBytes [64]byte
	for {
		if _, err := io.ReadFull(random, randomBytes[:pointSize]); err != nil {
			clear(randomBytes[:])
			return nil, err
		}
		k := curve.q.fromBytes(randomBytes[:pointSize])
		if fixedZeroMask(k) != 0 {
			continue
		}

		var x L
		var infinity uint64
		if curve.edwards {
			x, infinity = curve.edwardsX(curve.multiplyBaseEdwards(curve.q.normal(k)))
		} else {
			x, infinity = curve.projectiveX(curve.multiplyBaseProjective(curve.q.normal(k)))
		}
		if infinity != 0 {
			continue
		}
		r := curve.q.fromNormalLimbs(x)
		if fixedZeroMask(r) != 0 {
			continue
		}
		s := curve.q.add(curve.q.mul(d, r), curve.q.mul(k, e))
		if fixedZeroMask(s) != 0 {
			continue
		}

		signature := make([]byte, 2*pointSize)
		fixedPutBigEndian(signature[:pointSize], curve.q.normal(s))
		fixedPutBigEndian(signature[pointSize:], curve.q.normal(r))
		clear(randomBytes[:])
		return signature, nil
	}
}

func (curve *fixedCurve[L]) vkoRaw(private, ukm, x, y *big.Int) ([]byte, error) {
	if curve.edwards {
		point := curve.edwardsFromWeierstrass(curve.p.fromBig(x), curve.p.fromBig(y))
		point = curve.edwardsMultiplySmall(point, curve.cofactor)
		scalar := curve.q.mul(curve.q.fromBig(private), curve.q.fromBig(ukm))
		if fixedZeroMask(scalar) != 0 {
			return nil, errors.New("gogost/gost3410: Нулевая степень")
		}
		return curve.edwardsRawLE(curve.edwardsMultiply(point, curve.q.normal(scalar)))
	}
	point := curve.multiplySmall(curve.pointFromBig(x, y), curve.cofactor)
	if fixedZeroMask(point.z) != 0 {
		return nil, errors.New("gogost/gost3410: Точка на бесконечности")
	}
	scalar := curve.q.mul(curve.q.fromBig(private), curve.q.fromBig(ukm))
	if fixedZeroMask(scalar) != 0 {
		return nil, errors.New("gogost/gost3410: Нулевая степень")
	}
	return curve.affineRawLE(curve.multiply(point, curve.q.normal(scalar)))
}

type fixedBackendState struct {
	domain          curveDomain
	once            sync.Once
	c256            *fixedCurve[limbs256]
	c512            *fixedCurve[limbs512]
	validatedPoints atomic.Pointer[validatedPointCache]
}

// A named curve's immutable backend is shared by its mutable factory clones.
// Keep only successful, fully validated public points. A direct-mapped cache
// bounds memory and avoids retaining attacker-controlled certificate DER.
type validatedPointKey [16]uint64

type validatedPointEntry struct {
	key     validatedPointKey
	present bool
}

type validatedPointCache struct {
	mu      sync.RWMutex
	entries [64]validatedPointEntry
}

func newValidatedPointKey(x, y *big.Int) (key validatedPointKey) {
	xWords := fixedLimbsFromBig[limbs512](x)
	yWords := fixedLimbsFromBig[limbs512](y)
	copy(key[:8], xWords[:])
	copy(key[8:], yWords[:])
	return key
}

func (key validatedPointKey) slot() uint64 {
	hash := uint64(0x9e3779b97f4a7c15)
	for _, word := range key {
		hash = bits.RotateLeft64(hash^word, 13) * 0x9e3779b97f4a7c15
	}
	return hash & 63
}

func (state *fixedBackendState) hasValidatedPoint(curve *Curve, x, y *big.Int) bool {
	if state == nil {
		return false
	}
	cache := state.validatedPoints.Load()
	if cache == nil || !state.domain.matches(curve) {
		return false
	}
	key := newValidatedPointKey(x, y)
	cache.mu.RLock()
	entry := cache.entries[key.slot()]
	cache.mu.RUnlock()
	return entry.present && entry.key == key
}

func (state *fixedBackendState) rememberValidatedPoint(curve *Curve, x, y *big.Int) {
	if state == nil || !state.domain.matches(curve) {
		return
	}
	cache := state.validatedPoints.Load()
	if cache == nil {
		fresh := new(validatedPointCache)
		if state.validatedPoints.CompareAndSwap(nil, fresh) {
			cache = fresh
		} else {
			cache = state.validatedPoints.Load()
		}
	}
	key := newValidatedPointKey(x, y)
	cache.mu.Lock()
	cache.entries[key.slot()] = validatedPointEntry{key: key, present: true}
	cache.mu.Unlock()
}

func newFixedBackendState(curve *Curve) *fixedBackendState {
	return &fixedBackendState{domain: snapshotCurveDomain(curve)}
}

func (state *fixedBackendState) initialize() {
	bitLen := state.domain.p.BitLen()
	switch {
	case bitLen <= 256:
		state.c256, _ = newFixedCurve[limbs256](&state.domain)
	case bitLen <= 512:
		state.c512, _ = newFixedCurve[limbs512](&state.domain)
	}
}

func (state *fixedBackendState) get256(curve *Curve) *fixedCurve[limbs256] {
	if state == nil || !state.domain.matches(curve) {
		return nil
	}
	state.once.Do(state.initialize)
	return state.c256
}

func (state *fixedBackendState) get512(curve *Curve) *fixedCurve[limbs512] {
	if state == nil || !state.domain.matches(curve) {
		return nil
	}
	state.once.Do(state.initialize)
	return state.c512
}

func (state *fixedBackendState) expBase(curve *Curve, scalar *big.Int) (x, y *big.Int, err error, used bool) {
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(curve.Q) >= 0 {
		return nil, nil, nil, false
	}
	if fixed := state.get256(curve); fixed != nil {
		x, y, err = fixed.expBase(scalar)
		return x, y, err, true
	}
	if fixed := state.get512(curve); fixed != nil {
		x, y, err = fixed.expBase(scalar)
		return x, y, err, true
	}
	return nil, nil, nil, false
}

func (state *fixedBackendState) contains(curve *Curve, x, y *big.Int) (result, used bool) {
	if state == nil || x == nil || y == nil {
		return false, false
	}
	if fixed := state.get256(curve); fixed != nil {
		return fixed.contains(x, y), true
	}
	if fixed := state.get512(curve); fixed != nil {
		return fixed.contains(x, y), true
	}
	return false, false
}

func (state *fixedBackendState) pointInSubgroup(curve *Curve, x, y *big.Int) (result, used bool) {
	if state == nil || x == nil || y == nil {
		return false, false
	}
	if fixed := state.get256(curve); fixed != nil {
		if fixed.edwards {
			point := fixed.edwardsFromWeierstrass(fixed.p.fromBig(x), fixed.p.fromBig(y))
			if fixedZeroMask(point.z) == 0 {
				multiple := fixed.edwardsMultiplySubgroup(point)
				return fixedZeroMask(multiple.z) == 0 && fixedZeroMask(multiple.x) != 0 &&
					fixedEqualMask(multiple.y, multiple.z) != 0, true
			}
		}
		point := fixed.multiplySmall(fixed.pointFromBig(x, y), curve.Q)
		return fixedZeroMask(point.z) != 0, true
	}
	if fixed := state.get512(curve); fixed != nil {
		if fixed.edwards {
			point := fixed.edwardsFromWeierstrass(fixed.p.fromBig(x), fixed.p.fromBig(y))
			if fixedZeroMask(point.z) == 0 {
				multiple := fixed.edwardsMultiplySubgroup(point)
				return fixedZeroMask(multiple.z) == 0 && fixedZeroMask(multiple.x) != 0 &&
					fixedEqualMask(multiple.y, multiple.z) != 0, true
			}
		}
		point := fixed.multiplySmall(fixed.pointFromBig(x, y), curve.Q)
		return fixedZeroMask(point.z) != 0, true
	}
	return false, false
}

func (state *fixedBackendState) expPoint(curve *Curve, scalar, x, y *big.Int) (rx, ry *big.Int, err error, used bool) {
	if scalar == nil || scalar.Sign() <= 0 || scalar.Cmp(curve.Q) >= 0 || x == nil || y == nil {
		return nil, nil, nil, false
	}
	if fixed := state.get256(curve); fixed != nil {
		rx, ry, err = fixed.expPoint(scalar, x, y)
		return rx, ry, err, true
	}
	if fixed := state.get512(curve); fixed != nil {
		rx, ry, err = fixed.expPoint(scalar, x, y)
		return rx, ry, err, true
	}
	return nil, nil, nil, false
}

func (state *fixedBackendState) expDoublePublic(curve *Curve, baseScalar, pointScalar, x, y *big.Int) (rx, ry *big.Int, err error, used bool) {
	if baseScalar == nil || pointScalar == nil || baseScalar.Sign() < 0 || pointScalar.Sign() < 0 ||
		baseScalar.Cmp(curve.Q) >= 0 || pointScalar.Cmp(curve.Q) >= 0 || x == nil || y == nil {
		return nil, nil, nil, false
	}
	if fixed := state.get256(curve); fixed != nil {
		rx, ry, err = fixed.expDoublePublic(baseScalar, pointScalar, x, y)
		return rx, ry, err, true
	}
	if fixed := state.get512(curve); fixed != nil {
		rx, ry, err = fixed.expDoublePublic(baseScalar, pointScalar, x, y)
		return rx, ry, err, true
	}
	return nil, nil, nil, false
}

func (state *fixedBackendState) signDigest(curve *Curve, private *big.Int, digest []byte, random io.Reader) (signature []byte, err error, used bool) {
	if private == nil || private.Sign() <= 0 || private.Cmp(curve.Q) >= 0 {
		return nil, nil, false
	}
	if fixed := state.get256(curve); fixed != nil {
		signature, err = fixed.signDigest(private, digest, random)
		return signature, err, true
	}
	if fixed := state.get512(curve); fixed != nil {
		signature, err = fixed.signDigest(private, digest, random)
		return signature, err, true
	}
	return nil, nil, false
}

func (state *fixedBackendState) vko(curve *Curve, private, ukm, x, y *big.Int) (key []byte, err error, used bool) {
	// Reduction modulo Q is valid after cofactor clearing only for a point on
	// the canonical curve. Invalid or compatibility inputs retain the exact
	// legacy combined-scalar path.
	if private == nil || ukm == nil || x == nil || y == nil || private.Sign() <= 0 ||
		private.Cmp(curve.Q) >= 0 || ukm.Sign() < 0 {
		return nil, nil, false
	}
	if fixed := state.get256(curve); fixed != nil {
		if !fixed.contains(x, y) {
			return nil, nil, false
		}
		key, err = fixed.vkoRaw(private, ukm, x, y)
		return key, err, true
	}
	if fixed := state.get512(curve); fixed != nil {
		if !fixed.contains(x, y) {
			return nil, nil, false
		}
		key, err = fixed.vkoRaw(private, ukm, x, y)
		return key, err, true
	}
	return nil, nil, false
}
