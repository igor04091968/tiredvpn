package shipovnik

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
)

const syndromeKAT = "b9766033949c41bcca493f0afa958ab16e3f9b730c2123d70cd2b24b472b65afc9d1a3cd75a757aa29e2e046e8d700db548ccec6548e471c8d4a774731d08462baf676b4da89b759e6aae322f911beadf8fb85699c9b91302e4e1537dc34a45f2450e9ef243c1f8416d916467f144c984c3964343b2a3f209946e0b925c3c0072b185978f31adb8aae74ead0b8753e0f986ac2a8d6066fb33ccaaa875e4a4d255bc0388a687215b3cb4cf496560aa06560f378bfbf"

type deterministicReader struct {
	seed    [32]byte
	counter uint64
	block   [32]byte
	offset  int
}

type countingOnesReader struct {
	bytes int
}

type shortChunkReader struct {
	reader io.Reader
	max    int
}

func (r *shortChunkReader) Read(dst []byte) (int, error) {
	if len(dst) > r.max {
		dst = dst[:r.max]
	}
	return r.reader.Read(dst)
}

type errorAfterByteReader struct {
	err  error
	done bool
}

func (r *errorAfterByteReader) Read(dst []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	dst[0] = 0
	return 1, nil
}

type cancelingEntropyReader struct {
	reader *deterministicReader
	cancel context.CancelFunc
	limit  int
	read   int
}

func (r *cancelingEntropyReader) Read(dst []byte) (int, error) {
	n, err := r.reader.Read(dst)
	r.read += n
	if r.read >= r.limit {
		r.cancel()
	}
	return n, err
}

func (r *countingOnesReader) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = 0xff
	}
	r.bytes += len(dst)
	return len(dst), nil
}

func newDeterministicReader(label string) *deterministicReader {
	return &deterministicReader{seed: sha256.Sum256([]byte(label)), offset: 32}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	written := 0
	for len(p) != 0 {
		if r.offset == len(r.block) {
			var input [40]byte
			copy(input[:32], r.seed[:])
			binary.BigEndian.PutUint64(input[32:], r.counter)
			r.block = sha256.Sum256(input[:])
			r.counter++
			r.offset = 0
		}
		n := copy(p, r.block[r.offset:])
		r.offset += n
		written += n
		p = p[n:]
	}
	return written, nil
}

func fixedPrivateKey(t testing.TB, scheme Scheme) *PrivateKey {
	t.Helper()
	raw := make([]byte, PrivateKeySize)
	for bit := 0; bit < SecretWeight; bit++ {
		setBit(raw, bit)
	}
	key, err := scheme.NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type fixture struct {
	private   *PrivateKey
	public    *PublicKey
	message   []byte
	signature []byte
	err       error
}

var (
	articleFixtureOnce sync.Once
	articleFixtureData fixture
)

func articleFixture(t testing.TB) fixture {
	t.Helper()
	articleFixtureOnce.Do(func() {
		private := fixedPrivateKey(t, Article70())
		message := []byte("Shipovnik deterministic test message")
		signature, err := private.SignMessage(newDeterministicReader("article-fixture"), message, &Options{Workers: 4})
		articleFixtureData = fixture{
			private:   private,
			public:    private.Public().(*PublicKey),
			message:   message,
			signature: signature,
			err:       err,
		}
	})
	if articleFixtureData.err != nil {
		t.Fatal(articleFixtureData.err)
	}
	return articleFixtureData
}

func TestProfiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		scheme Scheme
		name   string
		rounds int
		min    int
		max    int
	}{
		{Reference(), "Shipovnik-Reference", 219, 200604, 1072662},
		{Article70(), "Shipovnik-Article70", 137, 125492, 671026},
	}
	for _, test := range tests {
		if test.scheme.Name() != test.name || test.scheme.Rounds() != test.rounds {
			t.Fatalf("profile metadata: got %q/%d", test.scheme.Name(), test.scheme.Rounds())
		}
		if test.scheme.MinSignatureSize() != test.min || test.scheme.MaxSignatureSize() != test.max {
			t.Fatalf("%s sizes: got [%d,%d], want [%d,%d]", test.name, test.scheme.MinSignatureSize(), test.scheme.MaxSignatureSize(), test.min, test.max)
		}
	}
	if err := (Scheme{}).validate(); !errors.Is(err, ErrInvalidScheme) {
		t.Fatalf("zero Scheme error = %v", err)
	}
	if PublicKeySize != 181 || PrivateKeySize != 362 {
		t.Fatalf("key sizes = %d/%d", PublicKeySize, PrivateKeySize)
	}
}

func TestMatrixAndSyndromeKAT(t *testing.T) {
	t.Parallel()
	if got := sha256.Sum256(hPrime); hex.EncodeToString(got[:]) != hPrimeSHA256 {
		t.Fatalf("matrix SHA-256 = %x", got)
	}
	key := fixedPrivateKey(t, Reference())
	if got := hex.EncodeToString(key.public[:]); got != syndromeKAT {
		t.Fatalf("syndrome KAT = %s", got)
	}
	var generic [PublicKeySize]byte
	syndromeGeneric(generic[:], key.data[:])
	if !bytes.Equal(generic[:], key.public[:]) {
		t.Fatal("selected backend differs from generic syndrome")
	}
}

func TestPermutationPackingKAT(t *testing.T) {
	t.Parallel()
	permutation := make([]uint16, CodeLength)
	for i := range permutation {
		permutation[i] = uint16(i)
	}
	packed := make([]byte, permutationPackedSize)
	packPermutation(packed, permutation)
	if got, want := packed[:9], []byte{0x00, 0x00, 0x01, 0x00, 0x20, 0x03, 0x00, 0x40, 0x05}; !bytes.Equal(got, want) {
		t.Fatalf("packed prefix = %x, want %x", got, want)
	}
	unpacked := make([]uint16, CodeLength)
	if err := validatePackedPermutation(packed); err != nil {
		t.Fatal(err)
	}
	unpackPermutation(unpacked, packed)
	for i, value := range unpacked {
		if value != uint16(i) {
			t.Fatalf("unpacked[%d] = %d", i, value)
		}
	}
}

func TestUniformLemireMapping(t *testing.T) {
	t.Parallel()

	var source entropySource
	source.ctx = context.Background()
	// For n=10 the rejection threshold is 6. Zero must be rejected; the
	// following maximum uint16 maps to 9.
	binary.LittleEndian.PutUint16(source.buf[0:2], 0)
	binary.LittleEndian.PutUint16(source.buf[2:4], ^uint16(0))
	source.n = 4
	got, err := source.uniform(10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 9 || source.off != 4 {
		t.Fatalf("uniform rejection: value=%d consumed=%d, want 9 and 4", got, source.off)
	}

	for _, test := range []struct {
		word uint16
		n    uint16
		want uint16
	}{
		{word: 0x7fff, n: 10, want: 4},
		{word: 0xffff, n: 2896, want: 2895},
		{word: 0xffff, n: 1, want: 0},
	} {
		var one entropySource
		one.ctx = context.Background()
		binary.LittleEndian.PutUint16(one.buf[:2], test.word)
		one.n = 2
		value, err := one.uniform(test.n)
		if err != nil {
			t.Fatal(err)
		}
		if value != test.want {
			t.Fatalf("uniform(%04x, %d) = %d, want %d", test.word, test.n, value, test.want)
		}
	}
}

func TestUniformLemireAllRanges(t *testing.T) {
	t.Parallel()
	data := make([]byte, 4096)
	if _, err := io.ReadFull(newDeterministicReader("lemire16-all-ranges"), data); err != nil {
		t.Fatal(err)
	}
	for n := uint16(1); n <= CodeLength; n++ {
		source, err := newEntropySource(context.Background(), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		word := 0
		for sample := 0; sample < 64; sample++ {
			var want uint16
			for {
				x := binary.LittleEndian.Uint16(data[word : word+2])
				word += 2
				product := uint64(x) * uint64(n)
				if uint16(product) < uint16((uint32(1)<<16)%uint32(n)) {
					continue
				}
				want = uint16(product >> 16)
				break
			}
			got, err := source.uniform(n)
			if err != nil {
				t.Fatalf("n=%d sample=%d: %v", n, sample, err)
			}
			if got != want || got >= n {
				t.Fatalf("n=%d sample=%d: got %d, want %d", n, sample, got, want)
			}
		}
		source.close()
	}
}

func TestUniformLemireShortReadsAndErrors(t *testing.T) {
	t.Parallel()
	data := make([]byte, len((entropySource{}).buf))
	binary.LittleEndian.PutUint16(data[0:2], 0)
	binary.LittleEndian.PutUint16(data[2:4], ^uint16(0))
	reader := &shortChunkReader{reader: bytes.NewReader(data), max: 1}
	source, err := newEntropySource(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.uniform(10)
	source.close()
	if err != nil || got != 9 {
		t.Fatalf("short-read rejection path: got=%d err=%v", got, err)
	}

	sentinel := errors.New("entropy sentinel")
	failing, err := newEntropySource(context.Background(), &errorAfterByteReader{err: sentinel})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.uniform(2896); !errors.Is(err, sentinel) {
		t.Fatalf("short entropy error = %v", err)
	}
	failing.close()

	var rejection entropySource
	rejection.ctx = context.Background()
	rejection.r = &errorAfterByteReader{err: sentinel, done: true}
	rejection.n = 2 // zero is rejected for n=10
	if _, err := rejection.uniform(10); !errors.Is(err, sentinel) {
		t.Fatalf("rejection refill error = %v", err)
	}
	rejection.close()
}

func TestParallelTwoPhaseBarrier(t *testing.T) {
	order := make([]uint16, 97)
	for i := range order {
		order[i] = uint16(i)
	}
	var validated, cryptographic atomic.Int64
	if err := parallelTwoPhase(context.Background(), order, 7, func(_, _ int) error {
		validated.Add(1)
		return nil
	}, func(_, _ int) error {
		if got := validated.Load(); got != int64(len(order)) {
			return errors.New("cryptographic phase crossed validation barrier")
		}
		cryptographic.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := cryptographic.Load(); got != int64(len(order)) {
		t.Fatalf("cryptographic calls = %d, want %d", got, len(order))
	}

	sentinel := errors.New("invalid response")
	validated.Store(0)
	cryptographic.Store(0)
	err := parallelTwoPhase(context.Background(), order, 7, func(_, item int) error {
		validated.Add(1)
		if item == len(order)-1 {
			return sentinel
		}
		return nil
	}, func(_, _ int) error {
		cryptographic.Add(1)
		return nil
	})
	if !errors.Is(err, sentinel) || cryptographic.Load() != 0 {
		t.Fatalf("validation failure: err=%v cryptographic=%d", err, cryptographic.Load())
	}
}

func TestApplyPermutationDifferential(t *testing.T) {
	t.Parallel()
	source, err := newEntropySource(context.Background(), newDeterministicReader("permutation-differential"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	vectorReader := newDeterministicReader("permutation-differential-vectors")

	for iteration := 0; iteration < 16; iteration++ {
		var vector, got, packedGot, want [PrivateKeySize]byte
		if _, err := io.ReadFull(vectorReader, vector[:]); err != nil {
			t.Fatal(err)
		}
		permutation := make([]uint16, CodeLength)
		if err := generatePermutation(source, permutation); err != nil {
			t.Fatal(err)
		}
		applyPermutation(got[:], permutation, vector[:])
		packed := make([]byte, permutationPackedSize)
		packPermutation(packed, permutation)
		applyPackedPermutation(packedGot[:], packed, vector[:])
		for output, input := range permutation {
			if vector[input>>3]&(1<<(7-uint(input&7))) != 0 {
				setBit(want[:], output)
			}
		}
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("iteration %d: optimized permutation differs from reference", iteration)
		}
		if !bytes.Equal(packedGot[:], want[:]) {
			t.Fatalf("iteration %d: packed permutation differs from reference", iteration)
		}
	}
}

func TestSecretScratchPoolsAreWiped(t *testing.T) {
	statePool := referenceSigningStates
	var heldStates []*signingState
	for {
		select {
		case state := <-statePool:
			heldStates = append(heldStates, state)
		default:
			goto statesDrained
		}
	}

statesDrained:
	state := newSigningState(Reference().Rounds())
	for i := range state.storage {
		state.storage[i] = 0xa5
	}
	releaseSigningState(Reference(), state)
	gotState := acquireSigningState(Reference())
	if gotState != state {
		t.Fatal("did not reacquire isolated signing state")
	}
	if !bytes.Equal(gotState.storage, make([]byte, len(gotState.storage))) {
		t.Fatal("signing state retained secret data")
	}
	releaseSigningState(Reference(), gotState)
	for _, old := range heldStates {
		releaseSigningState(Reference(), old)
	}

	var heldScratch []*roundScratch
	for {
		select {
		case scratch := <-roundScratches:
			heldScratch = append(heldScratch, scratch)
		default:
			goto scratchesDrained
		}
	}

scratchesDrained:
	scratch := new(roundScratch)
	for i := range scratch.temporary {
		scratch.temporary[i] = 0x5a
	}
	releaseRoundScratches([]*roundScratch{scratch})
	gotScratch := acquireRoundScratches(1)[0]
	if gotScratch != scratch {
		t.Fatal("did not reacquire isolated round scratch")
	}
	if !bytes.Equal(gotScratch.temporary[:], make([]byte, len(gotScratch.temporary))) {
		t.Fatal("round scratch retained secret data")
	}
	releaseRoundScratches([]*roundScratch{gotScratch})
	for _, old := range heldScratch {
		releaseRoundScratches([]*roundScratch{old})
	}

}

func TestChallengeMappingKAT(t *testing.T) {
	t.Parallel()
	for _, scheme := range []Scheme{Reference(), Article70()} {
		zero := challengeTrits(scheme, [hashSize]byte{})
		if !bytes.Equal(zero, make([]byte, scheme.Rounds())) {
			t.Fatalf("%s zero hash did not map to zero", scheme)
		}
		var maximum [hashSize]byte
		for i := range maximum {
			maximum[i] = 0xff
		}
		trits := challengeTrits(scheme, maximum)
		for i, trit := range trits {
			if trit != 2 {
				t.Fatalf("%s maximum hash trit[%d] = %d", scheme, i, trit)
			}
		}
	}
}

func TestChallengeMappingDifferential(t *testing.T) {
	t.Parallel()
	reader := newDeterministicReader("challenge-differential")
	for _, scheme := range []Scheme{Reference(), Article70()} {
		power := new(big.Int).Exp(big.NewInt(3), big.NewInt(int64(scheme.Rounds())), nil)
		for iteration := 0; iteration < 64; iteration++ {
			var hash [hashSize]byte
			if _, err := io.ReadFull(reader, hash[:]); err != nil {
				t.Fatal(err)
			}
			got := challengeTrits(scheme, hash)
			integer := new(big.Int).SetBytes(hash[:])
			integer.Mul(integer, power)
			integer.Rsh(integer, hashSize*8)
			digits := integer.Text(3)
			want := make([]byte, scheme.Rounds())
			for i, digit := range digits {
				want[len(want)-len(digits)+i] = byte(digit - '0')
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s iteration %d: challenge mapping differs", scheme, iteration)
			}
		}
	}
}

func TestKeyAPI(t *testing.T) {
	t.Parallel()
	private, err := Reference().GenerateKey(newDeterministicReader("keygen"))
	if err != nil {
		t.Fatal(err)
	}
	if hammingWeight(private.Bytes()) != SecretWeight {
		t.Fatal("generated private key has wrong weight")
	}
	privateCopy, err := NewPrivateKey(Reference(), private.Bytes())
	if err != nil || !private.Equal(privateCopy) {
		t.Fatalf("private round trip: equal=%v err=%v", private.Equal(privateCopy), err)
	}
	public := private.Public().(*PublicKey)
	publicCopy, err := NewPublicKey(Reference(), public.Bytes())
	if err != nil || !public.Equal(publicCopy) {
		t.Fatalf("public round trip: equal=%v err=%v", public.Equal(publicCopy), err)
	}
	articlePublic, err := Article70().NewPublicKey(public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if public.Equal(articlePublic) {
		t.Fatal("keys imported under different profiles compare equal")
	}
	if _, err := Reference().NewPrivateKey(make([]byte, PrivateKeySize)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("zero-weight private key error = %v", err)
	}
	if _, err := Reference().NewPublicKey(make([]byte, PublicKeySize-1)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short public key error = %v", err)
	}
}

func TestSignVerifyProfiles(t *testing.T) {
	article := articleFixture(t)
	if got := sha256.Sum256(article.signature); len(article.signature) != 523692 || hex.EncodeToString(got[:]) != "e8091314d3950c7dc6e0d5c14943e9c3b9a9bc75e96801e0a55a8e801442a424" {
		t.Fatalf("Article70 signature KAT: len=%d sha256=%x", len(article.signature), got)
	}
	valid, err := article.public.Verify(article.message, article.signature, &Options{Workers: 1})
	if err != nil || !valid {
		t.Fatalf("Article70 verify: valid=%v err=%v", valid, err)
	}
	if len(article.signature) < Article70().MinSignatureSize() || len(article.signature) > Article70().MaxSignatureSize() {
		t.Fatalf("Article70 signature length = %d", len(article.signature))
	}

	referencePrivate := fixedPrivateKey(t, Reference())
	referenceMessage := []byte("reference profile")
	referenceSignature, err := referencePrivate.SignMessage(newDeterministicReader("reference-fixture"), referenceMessage, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(referenceSignature); len(referenceSignature) != 797904 || hex.EncodeToString(got[:]) != "3362210689d4110ff40fa4a4a360346e13528f3f7956376252915e4c87d7620f" {
		t.Fatalf("Reference signature KAT: len=%d sha256=%x", len(referenceSignature), got)
	}
	valid, err = referencePrivate.Public().(*PublicKey).Verify(referenceMessage, referenceSignature, nil)
	if err != nil || !valid {
		t.Fatalf("Reference verify: valid=%v err=%v", valid, err)
	}
}

func TestWorkersDeterministic(t *testing.T) {
	fixture := articleFixture(t)
	serial, err := fixture.private.SignMessage(newDeterministicReader("workers"), fixture.message, &Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	parallel, err := fixture.private.SignMessage(newDeterministicReader("workers"), fixture.message, &Options{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serial, parallel) {
		t.Fatal("signature differs with worker count")
	}
	automatic, err := fixture.private.SignMessage(newDeterministicReader("workers"), fixture.message, &Options{Workers: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serial, automatic) {
		t.Fatal("signature differs in automatic worker mode")
	}
	prefix := []byte("prefix:")
	appended, err := fixture.private.SignMessageTo(append([]byte(nil), prefix...), newDeterministicReader("workers"), fixture.message, &Options{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(appended[:len(prefix)], prefix) || !bytes.Equal(appended[len(prefix):], serial) {
		t.Fatal("append-style signing result differs")
	}
}

func TestSigner(t *testing.T) {
	fixture := articleFixture(t)
	signer := crypto.Signer(fixture.private)
	if _, err := signer.Sign(newDeterministicReader("signer"), fixture.message, crypto.SHA256); !errors.Is(err, ErrPrehashedMessage) {
		t.Fatalf("prehashed Sign error = %v", err)
	}
	signature, err := signer.Sign(newDeterministicReader("signer"), fixture.message, Options{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := fixture.public.Verify(fixture.message, signature, nil)
	if err != nil || !valid {
		t.Fatalf("Signer signature: valid=%v err=%v", valid, err)
	}
}

func TestInvalidSignatureEncodingAndMismatch(t *testing.T) {
	fixture := articleFixture(t)
	checkInvalid := func(name string, signature []byte) {
		t.Helper()
		valid, err := fixture.public.Verify(fixture.message, signature, &Options{Workers: 2})
		if valid || !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("%s: valid=%v err=%v", name, valid, err)
		}
	}
	checkInvalid("truncated", fixture.signature[:len(fixture.signature)-1])
	checkInvalid("trailing byte", append(append([]byte(nil), fixture.signature...), 0))

	commitmentSize := Article70().Rounds() * commitmentRoundSize
	hash, err := hashMessageCommitments(context.Background(), fixture.message, fixture.signature[:commitmentSize])
	if err != nil {
		t.Fatal(err)
	}
	trits := challengeTrits(Article70(), hash)
	offsets := responseOffsets(commitmentSize, trits)

	longRound, shortRound := -1, -1
	for round, trit := range trits {
		if trit < 2 && longRound < 0 {
			longRound = round
		}
		if trit == 2 && shortRound < 0 {
			shortRound = round
		}
	}
	if longRound < 0 || shortRound < 0 {
		t.Fatal("fixture challenge lacks required trits")
	}

	duplicate := append([]byte(nil), fixture.signature...)
	packed := duplicate[offsets[longRound] : offsets[longRound]+permutationPackedSize]
	permutation := make([]uint16, CodeLength)
	unpackPermutation(permutation, packed)
	permutation[1] = permutation[0]
	packPermutation(packed, permutation)
	checkInvalid("duplicate permutation index", duplicate)

	outOfRange := append([]byte(nil), fixture.signature...)
	packed = outOfRange[offsets[longRound] : offsets[longRound]+permutationPackedSize]
	packed[0] = 0xff
	packed[1] = packed[1]&0x0f | 0xf0
	checkInvalid("out-of-range permutation index", outOfRange)

	wrongWeight := append([]byte(nil), fixture.signature...)
	revealedSecret := wrongWeight[offsets[shortRound]+PrivateKeySize : offsets[shortRound+1]]
	revealedSecret[0] ^= 0x80
	checkInvalid("wrong revealed weight", wrongWeight)

	cryptographicMismatch := append([]byte(nil), fixture.signature...)
	cryptographicMismatch[offsets[shortRound]] ^= 0x80
	valid, err := fixture.public.Verify(fixture.message, cryptographicMismatch, nil)
	if err != nil || valid {
		t.Fatalf("well-formed mismatch: valid=%v err=%v", valid, err)
	}

	wrongPublicRaw := fixture.public.Bytes()
	wrongPublicRaw[0] ^= 1
	wrongPublic, err := Article70().NewPublicKey(wrongPublicRaw)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = wrongPublic.Verify(fixture.message, fixture.signature, nil)
	if err != nil || valid {
		t.Fatalf("wrong public key: valid=%v err=%v", valid, err)
	}

	checkRejected := func(name string, public *PublicKey, message, signature []byte) {
		t.Helper()
		valid, err := public.Verify(message, signature, nil)
		if valid || (err != nil && !errors.Is(err, ErrInvalidSignature)) {
			t.Fatalf("%s: valid=%v err=%v", name, valid, err)
		}
	}
	changedMessage := append([]byte(nil), fixture.message...)
	changedMessage[0] ^= 1
	checkRejected("changed message", fixture.public, changedMessage, fixture.signature)

	changedCommitment := append([]byte(nil), fixture.signature...)
	changedCommitment[0] ^= 1
	checkRejected("changed commitment", fixture.public, fixture.message, changedCommitment)

	referencePublic, err := Reference().NewPublicKey(fixture.public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	checkRejected("wrong profile", referencePublic, fixture.message, fixture.signature)
}

func TestErrorsAndCancellation(t *testing.T) {
	fixture := articleFixture(t)
	if _, err := fixture.private.SignMessage(io.LimitReader(bytes.NewReader(make([]byte, 32)), 32), fixture.message, nil); err == nil {
		t.Fatal("entropy exhaustion was not reported")
	}
	if _, err := fixture.private.SignMessage(nil, fixture.message, nil); !errors.Is(err, ErrInvalidRandom) {
		t.Fatalf("nil entropy error = %v", err)
	}
	if _, err := fixture.private.SignMessage(newDeterministicReader("options"), fixture.message, &Options{Workers: -1}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("negative workers error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Article70().GenerateKeyContext(ctx, newDeterministicReader("cancel-keygen")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled keygen error = %v", err)
	}
	if _, err := fixture.private.SignMessageContext(ctx, newDeterministicReader("cancel-sign"), fixture.message, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sign error = %v", err)
	}
	if valid, err := fixture.public.VerifyContext(ctx, fixture.message, fixture.signature, nil); valid || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verify: valid=%v err=%v", valid, err)
	}
}

func TestSignPipelineEntropyFailurePreservesDestination(t *testing.T) {
	private := fixedPrivateKey(t, Reference())
	prefix := []byte("preserved-prefix")
	dst := append([]byte(nil), prefix...)
	random := io.LimitReader(newDeterministicReader("pipeline-entropy-failure"), 64<<10)
	result, err := private.SignMessageTo(dst, random, []byte("pipeline failure"), &Options{Workers: 4})
	if err == nil {
		t.Fatal("mid-pipeline entropy exhaustion was not reported")
	}
	if !bytes.Equal(result, prefix) {
		t.Fatalf("destination changed on pipeline failure: %x", result)
	}
}

func TestSignPipelineCancellationPreservesDestinationAndWipesScratch(t *testing.T) {
	private := fixedPrivateKey(t, Reference())
	prefix := []byte("cancellation-prefix")
	for _, limit := range []int{len((entropySource{}).buf), 256 << 10} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &cancelingEntropyReader{
			reader: newDeterministicReader("pipeline-cancellation"),
			cancel: cancel,
			limit:  limit,
		}
		dst := append([]byte(nil), prefix...)
		result, err := private.SignMessageToContext(ctx, dst, reader, []byte("pipeline cancellation"), &Options{Workers: 4})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("limit=%d: cancellation error = %v", limit, err)
		}
		if !bytes.Equal(result, prefix) {
			t.Fatalf("limit=%d: destination changed: %x", limit, result)
		}
	}

	var held []*roundScratch
	for {
		select {
		case scratch := <-roundScratches:
			held = append(held, scratch)
		default:
			goto drained
		}
	}

drained:
	if len(held) == 0 {
		t.Fatal("no returned scratch buffers found")
	}
	for _, scratch := range held {
		permutationCleared := true
		for _, value := range scratch.permutation {
			if value != 0 {
				permutationCleared = false
				break
			}
		}
		if !permutationCleared || scratch.generation != 0 ||
			!bytes.Equal(scratch.permuted[:], make([]byte, len(scratch.permuted))) ||
			!bytes.Equal(scratch.temporary[:], make([]byte, len(scratch.temporary))) ||
			!bytes.Equal(scratch.syndrome[:], make([]byte, len(scratch.syndrome))) {
			t.Fatal("canceled pipeline returned uncleared scratch")
		}
		releaseRoundScratches([]*roundScratch{scratch})
	}
}

func TestReferenceSignEntropyConsumption(t *testing.T) {
	private := fixedPrivateKey(t, Reference())
	random := new(countingOnesReader)
	message := []byte("entropy consumption")
	signature, err := private.SignMessage(random, message, &Options{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := private.Public().(*PublicKey).Verify(message, signature, &Options{Workers: 4})
	if err != nil || !valid {
		t.Fatalf("generated signature: valid=%v err=%v", valid, err)
	}
	bufferSize := len((entropySource{}).buf)
	rawBytes := Reference().Rounds() * (PrivateKeySize + 2*(CodeLength-1))
	want := (rawBytes + bufferSize - 1) / bufferSize * bufferSize
	if random.bytes != want {
		t.Fatalf("entropy bytes = %d, want %d", random.bytes, want)
	}
	oldRawBytes := Reference().Rounds() * (PrivateKeySize + 4*(CodeLength-1))
	oldRounded := (oldRawBytes + bufferSize - 1) / bufferSize * bufferSize
	if random.bytes*100 > oldRounded*55 {
		t.Fatalf("entropy reduction is below 45%%: old=%d new=%d", oldRounded, random.bytes)
	}
}

func TestConcurrentVerify(t *testing.T) {
	fixture := articleFixture(t)
	const goroutines = 8
	var wg sync.WaitGroup
	errorsChannel := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid, err := fixture.public.Verify(fixture.message, fixture.signature, &Options{Workers: 2})
			if err != nil {
				errorsChannel <- err
			} else if !valid {
				errorsChannel <- errors.New("signature rejected")
			}
		}()
	}
	wg.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func TestConcurrentSign(t *testing.T) {
	fixture := articleFixture(t)
	const goroutines = 4
	var wg sync.WaitGroup
	errorsChannel := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			signature, err := fixture.private.SignMessage(newDeterministicReader(string(rune('a'+index))), fixture.message, &Options{Workers: 2})
			if err != nil {
				errorsChannel <- err
				return
			}
			valid, err := fixture.public.Verify(fixture.message, signature, &Options{Workers: 2})
			if err != nil {
				errorsChannel <- err
			} else if !valid {
				errorsChannel <- errors.New("concurrent signature rejected")
			}
		}(i)
	}
	wg.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func responseOffsets(commitmentSize int, trits []byte) []int {
	offsets := make([]int, len(trits)+1)
	offsets[0] = commitmentSize
	for round, trit := range trits {
		size := longResponseSize
		if trit == 2 {
			size = shortResponseSize
		}
		offsets[round+1] = offsets[round] + size
	}
	return offsets
}
