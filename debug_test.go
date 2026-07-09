// Tests for the debug investigation surface — debug.go (six accessors and
// three toggle vars) and score_debug.go (sdbfScoreDebug, sdbfMaxScoreDebug,
// CompareDebug). Scheduled for removal together with the rest of the debug
// machinery. When that surface is removed, this file is deleted as a
// single unit.
//
// IMPORTANT: the three Debug* package-level vars are global mutable state.
// Tests in section IV that read or write them MUST NOT call t.Parallel()
// at any level. Each toggle subtest sets the toggles, registers a
// t.Cleanup to reset them, and runs sequentially. Because Go's test
// runner pauses parallel tests at t.Parallel() until all sequential tests
// complete, sequential tests have exclusive access to the toggles.

package sdhash

import (
	"encoding/base64"
	"math/bits"
	"testing"
)

// Test index
//
// I. debug.go accessors
// ├── 00010000  MaxElem stream and DD
// ├── 00020000  DDBlockSize stream and DD
// ├── 00030000  LastCount stream and DD
// ├── 00040000  ElemCount across all filters
// ├── 00050000  Hamming matches buffer recompute
// ├── 00060000  TotalElements equals sum over filters
// └── 00070000  All accessors survive parser round-trip
//
// II. score_debug.go private helpers (sdbfScoreDebug, sdbfMaxScoreDebug)
// ├── 00080000  sdbfScoreDebug zero bfCount returns -1
// ├── 00090000  sdbfScoreDebug both digests fully sparse returns -1
// ├── 00100000  sdbfMaxScoreDebug sparse source returns 0
// ├── 00110000  sdbfMaxScoreDebug no scoreable target returns -1
// ├── 00120000  sdbfScore and sdbfScoreDebug noTargetCount path
// └── 00130000  sdbfScoreDebug swap places the larger digest as the target
//
// III. CompareDebug interface contract
// ├── 00140000  CompareDebug nil other returns (0, false)
// ├── 00150000  CompareDebug foreign Sdbf returns (0, false)
// └── 00160000  CompareDebug degenerate pair returns (0, false)
//
// IV. CompareDebug toggle combinations (sequential — touches global state)
// └── 00170000  All four toggle combinations
//
// V. score_debug.go C++-faithful path coverage (sequential — touches global state)
// └── 00180000  sdbfScoreDebug C++-faithful sparse-source denominator-zero path
//
// VI. generate_debug.go (NewDebug construction chain — sequential, touches global state)
// ├── 00190000  NewDebug short buffer returns an error
// ├── 00200000  NewDebug stream round-trip at default toggles equals New
// ├── 00210000  NewDebug DD round-trip (multi-block) at default toggles equals New
// ├── 00220000  generateChunkSdbfDebug multi-chunk goroutine path
// ├── 00230000  NewDebug with double-count revert equals NewRef
// ├── 00240000  generateChunkSdbfDebug edge branches
// ├── 00250000  debug goroutine panic recovery
// ├── 00260000  populateSdbfDebug error propagation
// └── 00270000  NewDebug DD remainder block and histogram accumulation

// =========================================================================
// I. debug.go accessors
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  MaxElem stream and DD
// ---------------------------------------------------------------------------

// TestDebug_MaxElem verifies that MaxElem returns the documented per-mode
// element saturation cap: 160 for stream-mode digests and 192 for DD-mode
// digests.
func TestDebug_MaxElem(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 1, 1)

	stream := streamDigest(t, buf)
	checkEqual(t, uint32(160), MaxElem(stream),
		"MaxElem on stream-mode digest must be 160")

	dd := ddDigest(t, buf, 1<<16)
	checkEqual(t, uint32(192), MaxElem(dd),
		"MaxElem on DD-mode digest must be 192")
}

// ---------------------------------------------------------------------------
// 00020000  DDBlockSize stream and DD
// ---------------------------------------------------------------------------

// TestDebug_DDBlockSize verifies that DDBlockSize returns 0 for stream
// digests and the configured block size for DD digests.
func TestDebug_DDBlockSize(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 2, 2)

	stream := streamDigest(t, buf)
	checkEqual(t, uint32(0), DDBlockSize(stream),
		"DDBlockSize on stream-mode digest must be 0")

	const blockSize = uint32(1 << 16)
	dd := ddDigest(t, buf, blockSize)
	checkEqual(t, blockSize, DDBlockSize(dd),
		"DDBlockSize on DD-mode digest must equal the configured block size")
}

// ---------------------------------------------------------------------------
// 00030000  LastCount stream and DD
// ---------------------------------------------------------------------------

// TestDebug_LastCount verifies that LastCount returns the tail-filter
// element count for stream digests and 0 for DD digests (which do not
// track a separate last count — every filter has its own elemCount).
func TestDebug_LastCount(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 3, 3)

	stream := streamDigest(t, buf)
	got := LastCount(stream)
	checkAtMost(t, got, MaxElem(stream),
		"LastCount on stream digest must be ≤ MaxElem")

	dd := ddDigest(t, buf, 1<<16)
	checkEqual(t, uint32(0), LastCount(dd),
		"LastCount on DD-mode digest must be 0")
}

// ---------------------------------------------------------------------------
// 00040000  ElemCount across all filters
// ---------------------------------------------------------------------------

// TestDebug_ElemCount verifies ElemCount(s, i) for every filter index in
// both stream and DD modes. Stream-mode filters all hold MaxElem except
// the tail, which holds LastCount. DD-mode filters each track their own
// count via the elemCounts array.
func TestDebug_ElemCount(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 4, 4)

	// Stream mode: every filter except the last holds MaxElem; the last
	// holds LastCount.
	stream := streamDigest(t, buf)
	maxStream := MaxElem(stream)
	lastStream := LastCount(stream)
	for i := uint32(0); i < stream.FilterCount(); i++ {
		var want uint32
		if i < stream.FilterCount()-1 {
			want = maxStream
		} else {
			want = lastStream
		}
		checkEqual(t, want, ElemCount(stream, i),
			"stream ElemCount must equal MaxElem (non-tail) or LastCount (tail)")
	}

	// DD mode: every filter is in [0, MaxElem]. We can't pin exact values
	// without recomputing them, but we can verify the range and that the
	// accessor doesn't panic.
	dd := ddDigest(t, buf, 1<<16)
	maxDD := MaxElem(dd)
	for i := uint32(0); i < dd.FilterCount(); i++ {
		got := ElemCount(dd, i)
		checkAtMost(t, got, maxDD,
			"DD ElemCount must be ≤ MaxElem")
	}
}

// ---------------------------------------------------------------------------
// 00050000  Hamming matches buffer recompute
// ---------------------------------------------------------------------------

// TestDebug_Hamming verifies that Hamming(s, i) matches a fresh popcount
// over filter i's buffer slice. The internal hamming slice is computed
// once at construction; this test pins the relationship.
func TestDebug_Hamming(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 5, 5)
	stream := streamDigest(t, buf)
	inner := stream.(*sdbf)

	for i := uint32(0); i < stream.FilterCount(); i++ {
		var want uint16
		for _, b := range inner.buffer[i*inner.bfSize : (i+1)*inner.bfSize] {
			want += uint16(bits.OnesCount8(b))
		}
		checkEqual(t, want, Hamming(stream, i),
			"Hamming(s, i) must equal recomputed popcount over filter i")
	}
}

// ---------------------------------------------------------------------------
// 00060000  TotalElements equals sum over filters
// ---------------------------------------------------------------------------

// TestDebug_TotalElements verifies that TotalElements returns the sum of
// ElemCount across all filters, in both modes. This is the numerator of
// FeatureDensity, so the relationship is also pinned indirectly.
func TestDebug_TotalElements(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 6, 6)

	cases := []struct {
		name   string
		digest Sdbf
	}{
		{"stream", streamDigest(t, buf)},
		{"dd", ddDigest(t, buf, 1<<16)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var sum uint64
			for i := uint32(0); i < tc.digest.FilterCount(); i++ {
				sum += uint64(ElemCount(tc.digest, i))
			}
			checkEqual(t, sum, TotalElements(tc.digest),
				"TotalElements must equal sum of ElemCount over all filters")
		})
	}
}

// ---------------------------------------------------------------------------
// 00070000  All accessors survive parser round-trip
// ---------------------------------------------------------------------------

// TestDebug_AccessorsSurviveRoundTrip verifies that all six accessors
// return the same values on a digest before and after a String/Parse
// round-trip. This ensures the reference fields are populated identically
// from a wire-format string and from direct computation.
func TestDebug_AccessorsSurviveRoundTrip(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 7, 7)

	cases := []struct {
		name   string
		digest Sdbf
	}{
		{"stream", streamDigest(t, buf)},
		{"dd", ddDigest(t, buf, 1<<16)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseSdbfFromString(tc.digest.String())
			mustNoError(t, err, "round-trip parse must succeed")

			checkEqual(t, MaxElem(tc.digest), MaxElem(parsed),
				"MaxElem must survive round-trip")
			checkEqual(t, DDBlockSize(tc.digest), DDBlockSize(parsed),
				"DDBlockSize must survive round-trip")
			checkEqual(t, LastCount(tc.digest), LastCount(parsed),
				"LastCount must survive round-trip")
			checkEqual(t, TotalElements(tc.digest), TotalElements(parsed),
				"TotalElements must survive round-trip")
			checkEqual(t, tc.digest.FilterCount(), parsed.FilterCount(),
				"sanity: FilterCount must survive round-trip")

			for i := uint32(0); i < tc.digest.FilterCount(); i++ {
				checkEqual(t, ElemCount(tc.digest, i), ElemCount(parsed, i),
					"ElemCount must survive round-trip")
				checkEqual(t, Hamming(tc.digest, i), Hamming(parsed, i),
					"Hamming must survive round-trip")
			}
		})
	}
}

// =========================================================================
// II. score_debug.go private helpers (sdbfScoreDebug, sdbfMaxScoreDebug)
// =========================================================================

// ---------------------------------------------------------------------------
// 00080000  sdbfScoreDebug zero bfCount returns -1
// ---------------------------------------------------------------------------

// TestDebug_ScoreDebug_ZeroBfCount verifies the bfCount==0 guard in
// sdbfScoreDebug, which is the same shape as sdbfScore's. Default
// toggles (all false) take the additive-accumulation branch.
func TestDebug_ScoreDebug_ZeroBfCount(t *testing.T) {
	t.Parallel()

	emptyStream := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:0:0:\n"
	sd, err := ParseSdbfFromString(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	inner := sd.(*sdbf)
	checkEqual(t, -1, sdbfScoreDebug(inner, inner),
		"sdbfScoreDebug must return -1 when bfCount is 0")
}

// ---------------------------------------------------------------------------
// 00090000  sdbfScoreDebug both digests fully sparse returns -1
// ---------------------------------------------------------------------------

// TestDebug_ScoreDebug_DenominatorZero verifies that sdbfScoreDebug at
// default toggles (additive accumulation) follows the modern denominator
// rule: bfCount > 1 with all sparse filters zeroes the denominator and
// returns -1.
func TestDebug_ScoreDebug_DenominatorZero(t *testing.T) {
	t.Parallel()

	// base64.StdEncoding.EncodedLen(256) == 344: 85 full groups (340 chars) + 1-byte remainder ("AA==").
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))

	ddStr := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" +
		b64 + ":00:" + b64 + "\n"

	sd, err := ParseSdbfFromString(ddStr)
	mustNoError(t, err, "parsing a 2-filter all-sparse DD digest must succeed")

	inner := sd.(*sdbf)
	checkEqual(t, -1, sdbfScoreDebug(inner, inner),
		"sdbfScoreDebug must return -1 when all filters are sparse and bfCount > 1")
}

// ---------------------------------------------------------------------------
// 00100000  sdbfMaxScoreDebug sparse source returns 0
// ---------------------------------------------------------------------------

// TestDebug_MaxScoreDebug_SparseSource verifies the sparse-source guard
// in sdbfMaxScoreDebug, which mirrors sdbfMaxScore's behavior at default
// toggles.
func TestDebug_MaxScoreDebug_SparseSource(t *testing.T) {
	t.Parallel()

	src := &sdbf{
		bfSize:     bfSize,
		bfCount:    1,
		buffer:     make([]byte, bfSize),
		elemCounts: []uint16{1},
		hamming:    []uint16{0},
	}
	target := &sdbf{
		bfSize:  bfSize,
		bfCount: 0,
	}

	got := sdbfMaxScoreDebug(src, 0, target)
	checkEqual(t, float64(0), got,
		"sdbfMaxScoreDebug must return 0 when source filter is sparse")
}

// ---------------------------------------------------------------------------
// 00110000  sdbfMaxScoreDebug no scoreable target returns -1
// ---------------------------------------------------------------------------

// TestDebug_MaxScoreDebug_NoScoreableTarget verifies the maxScore=-1
// sentinel return from sdbfMaxScoreDebug when no target filter has enough
// elements to score against.
func TestDebug_MaxScoreDebug_NoScoreableTarget(t *testing.T) {
	t.Parallel()

	src := streamDigest(t, randomBuf(1<<20, 8, 8)).(*sdbf)
	checkAtLeast(t, src.elemCount(0), uint32(minElemCount),
		"sanity: source filter must be non-sparse")

	target := &sdbf{
		bfSize:     bfSize,
		bfCount:    2,
		buffer:     make([]byte, 2*bfSize),
		elemCounts: []uint16{1, 1},
		hamming:    []uint16{0, 0},
	}

	got := sdbfMaxScoreDebug(src, 0, target)
	checkEqual(t, float64(-1), got,
		"sdbfMaxScoreDebug must return -1 when every target filter is sparse")
}

// ---------------------------------------------------------------------------
// 00120000  sdbfScore and sdbfScoreDebug noTargetCount path
// ---------------------------------------------------------------------------

// TestDebug_ScoreDebug_NoTargetCount verifies the noTargetCount accumulation
// path in both sdbfScore and sdbfScoreDebug (modern branch). When every
// target filter is sparse (elemCount < minElemCount), sdbfMaxScore and
// sdbfMaxScoreDebug return -1 for every source filter, noTargetCount
// accumulates to bfCount1, denominator goes to 0, and both functions
// return -1. This covers the two statements — noTargetCount++ and continue
// — that high-entropy pairs never reach.
//
// The source must have FEWER filters than the sparse target so the swap
// guard (bfCount1 > sdbf2.bfCount) does not fire. If the source had more
// filters it would become sdbf2 after the swap, leaving the sparse digest
// as sdbf1; then sdbfMaxScore* would see a sparse SOURCE and return 0 (not
// -1), taking the sparseCount path instead of the noTargetCount path.
func TestDebug_ScoreDebug_NoTargetCount(t *testing.T) {
	t.Parallel()

	// Synthetic dense source: bfCount=1 (stream mode, elemCounts=nil),
	// lastCount=minElemCount so elemCount(0) == minElemCount. bfCount=1 is
	// strictly less than the 2-filter sparse target, so no swap occurs.
	denseSrc := &sdbf{
		bfSize:    bfSize,
		bfCount:   1,
		buffer:    make([]byte, bfSize),
		lastCount: minElemCount, // elemCount(0) returns lastCount in stream mode
		hamming:   []uint16{0},
		maxElem:   maxElem,
	}
	checkEqual(t, uint32(minElemCount), denseSrc.elemCount(0),
		"sanity: dense source filter must be at minElemCount")

	// Sparse target: 2 filters, both below minElemCount, so sdbfMaxScore*
	// returns -1 (not 0) — sparse TARGET triggers -1, sparse SOURCE triggers 0.
	sparseTarget := &sdbf{
		bfSize:     bfSize,
		bfCount:    2,
		buffer:     make([]byte, 2*bfSize),
		elemCounts: []uint16{1, 1},
		hamming:    []uint16{0, 0},
	}

	// sdbfScore: noTargetCount=1 == bfCount1=1 → denominator=0 → -1.
	checkEqual(t, -1, sdbfScore(denseSrc, sparseTarget),
		"sdbfScore must return -1 when all target filters are sparse (noTargetCount path)")

	// sdbfScoreDebug at default toggles (modern path): same result.
	checkEqual(t, -1, sdbfScoreDebug(denseSrc, sparseTarget),
		"sdbfScoreDebug must return -1 when all target filters are sparse (noTargetCount path)")
}

// ---------------------------------------------------------------------------
// 00130000  sdbfScoreDebug swap places the larger digest as the target
// ---------------------------------------------------------------------------

// TestDebug_ScoreDebug_Swap covers the swap block at the top of sdbfScoreDebug,
// which fires when the first argument has more filters than the second (so the
// smaller digest becomes the source). Passing the larger digest first must
// yield the same score as passing the smaller first — the swap makes the
// comparison order-independent.
func TestDebug_ScoreDebug_Swap(t *testing.T) {
	t.Parallel()

	large := streamDigest(t, randomBuf(1<<19, 71, 71)).(*sdbf) // many filters
	small := streamDigest(t, randomBuf(MinFileSize, 72, 72)).(*sdbf)
	checkGreater(t, large.bfCount, small.bfCount,
		"sanity: large digest must have more filters than small digest")

	largeFirst := sdbfScoreDebug(large, small) // triggers the swap
	smallFirst := sdbfScoreDebug(small, large) // no swap
	checkEqual(t, smallFirst, largeFirst,
		"sdbfScoreDebug must be order-independent via the swap block")
}

// =========================================================================
// III. CompareDebug interface contract
// =========================================================================

// ---------------------------------------------------------------------------
// 00140000  CompareDebug nil other returns (0, false)
// ---------------------------------------------------------------------------

// TestDebug_CompareDebug_NilOther verifies that CompareDebug returns
// (0, false) — not panicking — when either argument is the nil Sdbf
// interface value.
func TestDebug_CompareDebug_NilOther(t *testing.T) {
	t.Parallel()

	sd := streamDigest(t, randomBuf(1<<20, 9, 9))

	score, ok := CompareDebug(sd, nil)
	checkEqual(t, 0, score, "CompareDebug(s, nil) score must be 0")
	checkTrue(t, !ok, "CompareDebug(s, nil) ok must be false")

	score, ok = CompareDebug(nil, sd)
	checkEqual(t, 0, score, "CompareDebug(nil, s) score must be 0")
	checkTrue(t, !ok, "CompareDebug(nil, s) ok must be false")
}

// ---------------------------------------------------------------------------
// 00150000  CompareDebug foreign Sdbf returns (0, false)
// ---------------------------------------------------------------------------

// TestDebug_CompareDebug_ForeignOther verifies that CompareDebug returns
// (0, false) when either argument is a foreign Sdbf implementation.
// Mirrors the Compare and CompareRef foreign-impl guards.
func TestDebug_CompareDebug_ForeignOther(t *testing.T) {
	t.Parallel()

	sd := streamDigest(t, randomBuf(1<<20, 10, 10))
	foreign := &foreignSdbfImpl{}

	checkNotPanics(t, func() {
		score, ok := CompareDebug(sd, foreign)
		checkEqual(t, 0, score, "CompareDebug with foreign target score must be 0")
		checkTrue(t, !ok, "CompareDebug with foreign target ok must be false")
	}, "CompareDebug with a foreign Sdbf must not panic")

	checkNotPanics(t, func() {
		score, ok := CompareDebug(foreign, sd)
		checkEqual(t, 0, score, "CompareDebug with foreign source score must be 0")
		checkTrue(t, !ok, "CompareDebug with foreign source ok must be false")
	}, "CompareDebug with a foreign Sdbf as the receiver must not panic")
}

// ---------------------------------------------------------------------------
// 00160000  CompareDebug degenerate pair returns (0, false)
// ---------------------------------------------------------------------------

// TestDebug_CompareDebug_DegeneratePair verifies the score < 0 branch inside
// CompareDebug. All other CompareDebug callers in the suite use high-entropy
// pairs that always produce a valid score, leaving this branch uncovered.
// A zero-filter digest forces sdbfScoreDebug to return -1 immediately via the
// bfCount1 == 0 guard, which is the simplest way to drive score < 0.
func TestDebug_CompareDebug_DegeneratePair(t *testing.T) {
	t.Parallel()

	emptyStream := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:0:0:\n"
	sd, err := ParseSdbfFromString(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	score, ok := CompareDebug(sd, sd)
	checkEqual(t, 0, score, "CompareDebug on degenerate pair must return score 0")
	checkTrue(t, !ok, "CompareDebug on degenerate pair must return ok=false")
}

// =========================================================================
// IV. CompareDebug toggle combinations (sequential — touches global state)
// =========================================================================

// ---------------------------------------------------------------------------
// 00170000  All four toggle combinations
// ---------------------------------------------------------------------------

// TestDebug_CompareDebug_AllToggleCombinations exercises all 2^2 = 4
// combinations of the two Debug* toggle vars and verifies the well-
// formedness of CompareDebug's output in each. Two combinations carry
// strong equivalence assertions:
//
//   - all-off (defaults): CompareDebug must equal Compare exactly.
//   - {Acc=true, Pop=true}: CompareDebug must equal CompareRef
//     (modulo the (int, bool) vs int-with-sentinel return shape). This is
//     the combo that exactly reproduces sdbfScoreRef.
//
// The other two combinations are smoke-tested: result is well-formed
// (score in [0, 100] when ok, score=0 when !ok) and the call doesn't
// panic. The corpus tests under the compat tag pin the wider behavior;
// this test pins the unit-level contract of each toggle combination.
//
// This test does NOT call t.Parallel anywhere because the toggles are
// global state. Each subtest registers a t.Cleanup that resets both
// toggles to false, so a panic mid-subtest cannot leak state.
func TestDebug_CompareDebug_AllToggleCombinations(t *testing.T) {
	a := streamDigest(t, randomBuf(1<<20, 11, 11))
	b := streamDigest(t, randomBuf(1<<20, 12, 12))

	cases := []struct {
		name string
		acc  bool
		pop  bool
	}{
		{"all-off", false, false},
		{"acc-only", true, false},
		{"pop-only", false, true},
		{"acc+pop", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			DebugRevertAdditiveAccumulation = tc.acc
			DebugRevertExactPopcount = tc.pop
			t.Cleanup(func() {
				DebugRevertAdditiveAccumulation = false
				DebugRevertExactPopcount = false
			})

			score, ok := CompareDebug(a, b)

			// Smoke check: result is well-formed.
			if ok {
				checkAtLeast(t, score, 0,
					"CompareDebug score must be ≥ 0 when ok is true")
				checkAtMost(t, score, 100,
					"CompareDebug score must be ≤ 100 when ok is true")
			} else {
				checkEqual(t, 0, score,
					"CompareDebug score must be 0 when ok is false")
			}

			// Equivalence assertions for the two anchor combinations.
			switch {
			case !tc.acc && !tc.pop:
				// all-off: CompareDebug must exactly equal Compare.
				wantScore, wantOk := a.Compare(b)
				checkEqual(t, wantScore, score,
					"all-off CompareDebug score must equal Compare score")
				checkEqual(t, wantOk, ok,
					"all-off CompareDebug ok must equal Compare ok")

			case tc.acc && tc.pop:
				// {Acc=true, Pop=true}: CompareDebug must equal
				// CompareRef modulo return shape.
				refScore := a.CompareRef(b)
				if refScore < 0 {
					checkTrue(t, !ok,
						"CompareDebug ok must be false when CompareRef returns -1")
					checkEqual(t, 0, score,
						"CompareDebug score must be 0 when ok is false")
				} else {
					checkTrue(t, ok,
						"CompareDebug ok must be true when CompareRef returns ≥ 0")
					checkEqual(t, refScore, score,
						"acc+pop CompareDebug score must equal CompareRef score")
				}
			}
		})
	}
}

// =========================================================================
// V. score_debug.go C++-faithful path coverage (sequential — touches global state)
// =========================================================================

// ---------------------------------------------------------------------------
// 00180000  sdbfScoreDebug C++-faithful sparse-source denominator-zero path
// ---------------------------------------------------------------------------

// TestDebug_ScoreDebug_CppFaithfulSparseSource verifies three statements in
// the DebugRevertAdditiveAccumulation=true branch that high-entropy pairs
// cannot reach:
//
//   - sparseCount++ inside the C++-faithful loop: fires when a source filter
//     has elemCount < minElemCount (sdbfMaxScoreDebug returns 0, not -1, so
//     the score is non-negative and the loop body does not skip it).
//   - scoreSum = -1 when denominator drops to zero: fires when sparseCount
//     equals bfCount1 and bfCount1 > 1.
//   - return -1 after the scoreSum < 0 check: follows immediately.
//
// Using a 2-filter DD digest with both filters at elemCount=0 guarantees
// sparseCount=2 after the loop, denominator=2−2=0, scoreSum reset to -1,
// and the function returns -1.
//
// This test does NOT call t.Parallel because it writes global toggle state.
// t.Cleanup resets all three toggles so a panic cannot leak state.
func TestDebug_ScoreDebug_CppFaithfulSparseSource(t *testing.T) {
	DebugRevertAdditiveAccumulation = true
	t.Cleanup(func() {
		DebugRevertAdditiveAccumulation = false
		DebugRevertExactPopcount = false
	})

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	ddStr := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" +
		b64 + ":00:" + b64 + "\n"

	sd, err := ParseSdbfFromString(ddStr)
	mustNoError(t, err, "parsing a 2-filter all-sparse DD digest must succeed")
	inner := sd.(*sdbf)

	checkEqual(t, -1, sdbfScoreDebug(inner, inner),
		"sdbfScoreDebug in C++-faithful mode must return -1 when all source filters are sparse")
}

// =========================================================================
// VI. generate_debug.go (NewDebug construction chain)
//
// Sequential — generateChunkScoresDebug reads DebugRevertChunkScoresDoubleCount,
// a global toggle. None of these tests call t.Parallel(); the revert test sets
// the toggle and registers a t.Cleanup to reset it.
// =========================================================================

// ---------------------------------------------------------------------------
// 00190000  NewDebug short buffer returns an error
// ---------------------------------------------------------------------------

// TestDebug_NewDebug_ShortBuffer verifies NewDebug rejects a buffer below the
// minimum input size, mirroring New.
func TestDebug_NewDebug_ShortBuffer(t *testing.T) {
	_, err := NewDebug(make([]byte, MinFileSize-1))
	checkError(t, err, "NewDebug must error on a buffer shorter than MinFileSize")
}

// ---------------------------------------------------------------------------
// 00200000  NewDebug stream round-trip at default toggles equals New
// ---------------------------------------------------------------------------

// TestDebug_NewDebug_StreamDefaultEqualsNew drives the debug stream chain
// (NewDebug -> createSdbfDebug -> populateSdbfDebug -> generateChunkSdbfDebug ->
// generateChunkScoresDebug else-branch) and confirms that at default toggles it
// reproduces the modern New digest exactly.
func TestDebug_NewDebug_StreamDefaultEqualsNew(t *testing.T) {
	buf := randomBuf(1<<19, 21, 21)

	dbgFactory, err := NewDebug(buf)
	mustNoError(t, err, "NewDebug must accept a valid buffer")
	dbgSD, err := dbgFactory.Compute()
	mustNoError(t, err, "debug stream Compute must not error")

	modFactory, err := New(buf)
	mustNoError(t, err, "New must accept the buffer")
	modSD, err := modFactory.Compute()
	mustNoError(t, err, "modern stream Compute must not error")

	checkEqual(t, modSD.String(), dbgSD.String(),
		"NewDebug at default toggles must equal New (stream)")
}

// ---------------------------------------------------------------------------
// 00210000  NewDebug DD round-trip (multi-block) at default toggles equals New
// ---------------------------------------------------------------------------

// TestDebug_NewDebug_DDDefaultEqualsNew drives the debug block chain
// (populateSdbfDebug block branch -> generateBlockSdbfDebug ->
// generateSingleBlockSdbfDebug) with a 1 MiB buffer and 64 KiB blocks (16
// blocks, parallel pool) and confirms it matches New at default toggles.
func TestDebug_NewDebug_DDDefaultEqualsNew(t *testing.T) {
	buf := randomBuf(1<<20, 22, 22)

	dbgFactory, err := NewDebug(buf)
	mustNoError(t, err, "NewDebug must accept a valid buffer")
	dbgSD, err := dbgFactory.WithBlockSize(1 << 16).Compute()
	mustNoError(t, err, "debug DD Compute must not error")

	modFactory, err := New(buf)
	mustNoError(t, err, "New must accept the buffer")
	modSD, err := modFactory.WithBlockSize(1 << 16).Compute()
	mustNoError(t, err, "modern DD Compute must not error")

	checkEqual(t, modSD.String(), dbgSD.String(),
		"NewDebug at default toggles must equal New (DD)")
}

// ---------------------------------------------------------------------------
// 00220000  generateChunkSdbfDebug multi-chunk goroutine path
// ---------------------------------------------------------------------------

// TestDebug_GenerateChunkSdbfDebug_MultiChunk exercises the parallel goroutine
// phase of the debug stream path by calling generateChunkSdbfDebug directly
// with a 1 MiB chunk size and a 3.5 MiB buffer, mirroring the modern and
// reference multi-chunk tests.
func TestDebug_GenerateChunkSdbfDebug_MultiChunk(t *testing.T) {
	const chunkSize = 1 << 20
	const totalSize = 3*chunkSize + chunkSize/2

	buf := randomBuf(totalSize, 23, 23)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(totalSize)

	mustNoError(t, sd.generateChunkSdbfDebug(buf, chunkSize),
		"generateChunkSdbfDebug must not error on valid multi-chunk input")
	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "multi-chunk debug digest must have at least one filter")
	checkEqual(t, 100, sdbfScore(sd, sd), "multi-chunk debug digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00230000  NewDebug with double-count revert equals NewRef
// ---------------------------------------------------------------------------

// TestDebug_NewDebug_RevertEqualsRef sets DebugRevertChunkScoresDoubleCount,
// exercising the C++-faithful branch of generateChunkScoresDebug, and confirms
// that NewDebug then reproduces the NewRef digest in both stream and DD modes.
//
//goland:noinspection GoDeprecation
func TestDebug_NewDebug_RevertEqualsRef(t *testing.T) {
	DebugRevertChunkScoresDoubleCount = true
	t.Cleanup(func() { DebugRevertChunkScoresDoubleCount = false })

	buf := randomBuf(1<<20, 24, 24)

	// Stream
	dbgStream, err := NewDebug(buf)
	mustNoError(t, err, "NewDebug must accept a valid buffer")
	dbgStreamSD, err := dbgStream.Compute()
	mustNoError(t, err, "debug revert stream Compute must not error")

	refStream, err := NewRef(buf)
	mustNoError(t, err, "NewRef must accept a valid buffer")
	refStreamSD, err := refStream.Compute()
	mustNoError(t, err, "reference stream Compute must not error")

	checkEqual(t, refStreamSD.String(), dbgStreamSD.String(),
		"NewDebug with double-count revert must equal NewRef (stream)")

	// DD
	dbgDD, err := NewDebug(buf)
	mustNoError(t, err, "NewDebug must accept a valid buffer")
	dbgDDSD, err := dbgDD.WithBlockSize(1 << 16).Compute()
	mustNoError(t, err, "debug revert DD Compute must not error")

	refDD, err := NewRef(buf)
	mustNoError(t, err, "NewRef must accept a valid buffer")
	refDDSD, err := refDD.WithBlockSize(1 << 16).Compute()
	mustNoError(t, err, "reference DD Compute must not error")

	checkEqual(t, refDDSD.String(), dbgDDSD.String(),
		"NewDebug with double-count revert must equal NewRef (DD)")
}

// ---------------------------------------------------------------------------
// 00240000  generateChunkSdbfDebug edge branches
// ---------------------------------------------------------------------------

// TestDebug_GenerateChunkSdbfDebug_Edges covers the single-chunk edge branches
// of the debug stream path at default toggles: chunk-size guard, qt==1 exact
// chunk, and both the multi-chunk and single-chunk sparse-last-filter pruning.
func TestDebug_GenerateChunkSdbfDebug_Edges(t *testing.T) {
	t.Run("chunk size too small", func(t *testing.T) {
		buf := randomBuf(MinFileSize, 41, 41)
		sd := newTestSdbf(t)
		sd.origFileSize = uint64(MinFileSize)
		checkError(t, sd.generateChunkSdbfDebug(buf, uint64(popWinSize)),
			"generateChunkSdbfDebug chunkSize <= popWinSize must return an error")
	})

	t.Run("exactly one chunk", func(t *testing.T) {
		const size = 1 << 19
		buf := randomBuf(size, 42, 42)
		sd := newTestSdbf(t)
		sd.origFileSize = uint64(size)
		mustNoError(t, sd.generateChunkSdbfDebug(buf, size), "generateChunkSdbfDebug must not error")
		sd.computeHamming()
		checkEqual(t, 100, sdbfScore(sd, sd), "exactly-one-chunk debug digest must self-compare at 100")
	})

	t.Run("multi-chunk sparse last filter", func(t *testing.T) {
		const chunkSize = 10240
		buf := make([]byte, 2*chunkSize)
		copy(buf[:chunkSize], randomBuf(chunkSize, 1, 1))
		sd := newTestSdbf(t)
		sd.origFileSize = uint64(len(buf))
		mustNoError(t, sd.generateChunkSdbfDebug(buf, chunkSize), "generateChunkSdbfDebug must not error")
		sd.computeHamming()
		checkEqual(t, uint32(1), sd.bfCount, "multi-chunk sparse pruning must reduce bfCount to 1")
	})

	t.Run("single-chunk sparse last filter", func(t *testing.T) {
		const size = 20480
		buf := make([]byte, size)
		copy(buf[:size/2], randomBuf(size/2, 1, 1))
		sd := newTestSdbf(t)
		sd.origFileSize = uint64(size)
		mustNoError(t, sd.generateChunkSdbfDebug(buf, size), "generateChunkSdbfDebug must not error")
		sd.computeHamming()
		checkEqual(t, uint32(1), sd.bfCount, "single-chunk sparse pruning must reduce bfCount to 1")
	})
}

// ---------------------------------------------------------------------------
// 00250000  debug goroutine panic recovery
// ---------------------------------------------------------------------------

// TestDebug_GenerateSdbfDebug_GoroutinePanicRecovery covers the panicErr paths
// of both the debug multi-chunk and block goroutine phases.
func TestDebug_GenerateSdbfDebug_GoroutinePanicRecovery(t *testing.T) {
	t.Run("chunk", func(t *testing.T) {
		const chunkSize = 1 << 20
		buf := randomBuf(4*chunkSize, 100, 100)
		sd := newTestSdbf(t)
		sd.origFileSize = uint64(len(buf))
		sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }
		var err error
		checkNotPanics(t, func() { err = sd.generateChunkSdbfDebug(buf, chunkSize) },
			"generateChunkSdbfDebug must not propagate a goroutine panic")
		checkError(t, err, "generateChunkSdbfDebug must return an error when a goroutine panics")
	})

	t.Run("block", func(t *testing.T) {
		const ddBlockSize = 1024
		buf := randomBuf(1<<20, 101, 101)
		sd := newTestSdbf(t)
		sd.ddBlockSize = ddBlockSize
		sd.maxElem = maxElemDd
		sd.origFileSize = uint64(len(buf))
		sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }
		var err error
		checkNotPanics(t, func() { err = sd.generateBlockSdbfDebug(buf) },
			"generateBlockSdbfDebug must not propagate a goroutine panic")
		checkError(t, err, "generateBlockSdbfDebug must return an error when a goroutine panics")
	})
}

// ---------------------------------------------------------------------------
// 00260000  populateSdbfDebug error propagation
// ---------------------------------------------------------------------------

// TestDebug_PopulateSdbfDebug_ErrorPropagation covers the stream and block
// error-propagation branches of populateSdbfDebug and the ddBlockSize guard.
func TestDebug_PopulateSdbfDebug_ErrorPropagation(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		buf := make([]byte, 33<<20)
		sd := newTestSdbf(t)
		sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }
		var err error
		checkNotPanics(t, func() { _, err = populateSdbfDebug(sd, buf, 0) },
			"populateSdbfDebug must not propagate a goroutine panic")
		checkError(t, err, "populateSdbfDebug must propagate a stream error")
	})

	t.Run("block", func(t *testing.T) {
		const ddBlockSize = 1024
		buf := randomBuf(4*ddBlockSize, 201, 201)
		sd := newTestSdbf(t)
		sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }
		var err error
		checkNotPanics(t, func() { _, err = populateSdbfDebug(sd, buf, ddBlockSize) },
			"populateSdbfDebug must not propagate a goroutine panic")
		checkError(t, err, "populateSdbfDebug must propagate a block error")
	})

	t.Run("block size too small", func(t *testing.T) {
		buf := randomBuf(MinFileSize, 202, 202)
		sd := newTestSdbf(t)
		_, err := populateSdbfDebug(sd, buf, uint32(popWinSize)-1)
		checkError(t, err, "populateSdbfDebug must error when ddBlockSize < popWinSize")
	})
}

// ---------------------------------------------------------------------------
// 00270000  NewDebug DD remainder block and histogram accumulation
// ---------------------------------------------------------------------------

// TestDebug_NewDebug_DDEdges covers the trailing remainder-block branch of
// generateBlockSdbfDebug and the histogram-accumulation loop in
// generateSingleBlockSdbfDebug.
func TestDebug_NewDebug_DDEdges(t *testing.T) {
	t.Run("remainder block", func(t *testing.T) {
		buf := randomBuf(3*(1<<16)+(1<<15), 33, 33)
		factory, err := NewDebug(buf)
		mustNoError(t, err, "NewDebug must accept the buffer")
		sd, err := factory.WithBlockSize(1 << 16).Compute()
		mustNoError(t, err, "debug DD remainder Compute must not error")
		score, ok := sd.Compare(sd)
		checkEqual(t, true, ok, "debug DD remainder self-compare must be scoreable")
		checkEqual(t, 100, score, "debug DD remainder digest must self-compare at 100")
	})

	t.Run("moderate density", func(t *testing.T) {
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = byte(i % 64)
		}
		factory, err := NewDebug(buf)
		mustNoError(t, err, "NewDebug must accept the buffer")
		sd, err := factory.WithBlockSize(1 << 16).Compute()
		mustNoError(t, err, "debug DD moderate-density Compute must not error")
		if sd.String() == "" {
			t.Error("moderate-density debug DD digest must be non-empty")
		}
	})
}
