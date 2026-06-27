// Tests for the C++ reference compatibility surface — bloom_ref.go,
// score_ref.go, and the Sdbf.CompareRef method on the interface.
// Scheduled for removal alongside that surface at 1.0.0. When the
// surface is removed, this file is deleted as a single unit; no
// edits to other test files are required as part of the removal.

package sdhash

import (
	"testing"
)

// Test index
//
// I. bloom_ref.go (andPopcountCut)
// ├── 00010000  Zero overlap returns 0
// ├── 00020000  Full overlap matches andPopcount
// ├── 00030000  Stage 1 early-exit
// ├── 00040000  Stage 2 early-exit
// ├── 00050000  Stage 3 early-exit
// ├── 00060000  No early-exit runs to completion
// ├── 00070000  CutOff zero disables early-exit
// └── 00080000  Slack parameter behavior
//
// II. score_ref.go (sdbfScoreRef, sdbfMaxScoreRef)
// ├── 00090000  sdbfScoreRef zero bfCount returns -1
// ├── 00100000  sdbfScoreRef both digests fully sparse returns -1
// ├── 00110000  sdbfMaxScoreRef sparse source returns 0
// └── 00120000  sdbfMaxScoreRef no scoreable target returns -1
//
// III. Sdbf.CompareRef
// ├── 00130000  CompareRef nil other returns -1
// ├── 00140000  CompareRef foreign Sdbf returns -1
// ├── 00150000  CompareRef self-compare returns 100
// └── 00160000  CompareRef returns valid score on random pair

// =========================================================================
// I. bloom_ref.go (andPopcountCut)
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Zero overlap returns 0
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_ZeroOverlap verifies that two filters with no
// overlapping set bits produce a count of 0. Stage 1 sees count=0 and
// 8*0 + 48 < 100, so the function returns 0 from the stage-1 short-circuit.
func TestRef_AndPopcountCut_ZeroOverlap(t *testing.T) {
	t.Parallel()

	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	bf2[0] = 0xff // bf1 has all zeros, bf2 has 8 bits set, AND has 0.

	checkEqual(t, uint32(0), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 0")

	got := andPopcountCut(bf1, bf2, 100, 48)
	checkEqual(t, uint32(0), got,
		"zero overlap must return 0 (stage 1 short-circuit fires)")
}

// ---------------------------------------------------------------------------
// 00020000  Full overlap matches andPopcount
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_FullOverlap verifies that two identical all-ones
// filters produce the full popcount (2048) and that no stage check fires
// because the running count is always far above the cutoff plus slack.
func TestRef_AndPopcountCut_FullOverlap(t *testing.T) {
	t.Parallel()

	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := range bf1 {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(2048), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 2048 (256 bytes * 8 bits)")

	got := andPopcountCut(bf1, bf2, 100, 48)
	checkEqual(t, uint32(2048), got,
		"full overlap must return full popcount (no early-exit fires)")
}

// ---------------------------------------------------------------------------
// 00030000  Stage 1 early-exit
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_Stage1EarlyExit verifies the first staged check
// (after bytes 0–31). The first 32 bytes have zero overlap; the rest have
// full overlap. The function must short-circuit after stage 1 and return 0
// even though the full popcount would be 1792.
func TestRef_AndPopcountCut_Stage1EarlyExit(t *testing.T) {
	t.Parallel()

	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 32; i < 256; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(1792), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 1792 (224 bytes * 8 bits)")

	// Stage 1: count = 0. Check: 8*0 + 48 = 48 < 100 → return 0.
	got := andPopcountCut(bf1, bf2, 100, 48)
	checkEqual(t, uint32(0), got,
		"stage 1 early-exit must return 0 when 8*count + slack < cutOff")
}

// ---------------------------------------------------------------------------
// 00040000  Stage 2 early-exit
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_Stage2EarlyExit verifies the second staged check
// (after bytes 32–63). Stage 1 contributes 64 (8 bytes of overlap),
// stage 2 contributes 0 (no overlap), and stage 1's 4*64 + 48 = 304 < 400
// triggers the stage-2 short-circuit.
func TestRef_AndPopcountCut_Stage2EarlyExit(t *testing.T) {
	t.Parallel()

	// Bytes 0–7: overlap → stage 1 contributes 64.
	// Bytes 32–63: zero → stage 2 contributes 0.
	// Bytes 64–255: overlap → stages 3–4 would contribute 1536 if reached.
	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 0; i < 8; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}
	for i := 64; i < 256; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(1600), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 1600 (8 + 192 bytes * 8 bits)")

	// Stage 1 check: 8*64 + 48 = 560 ≥ 400 → continue.
	// Stage 2 check: 4*64 + 48 = 304 < 400 → return 0.
	got := andPopcountCut(bf1, bf2, 400, 48)
	checkEqual(t, uint32(0), got,
		"stage 2 early-exit must return 0 when 4*count + slack < cutOff")
}

// ---------------------------------------------------------------------------
// 00050000  Stage 3 early-exit
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_Stage3EarlyExit verifies the third staged check
// (after bytes 64–127). Stages 1 and 2 contribute 200 (25 bytes * 8 bits),
// stage 3 contributes 0, and 2*200 + 48 = 448 < 600 fires the stage-3
// short-circuit. The full popcount would be 1224 if stage 4 ran.
func TestRef_AndPopcountCut_Stage3EarlyExit(t *testing.T) {
	t.Parallel()

	// Bytes 0–24: overlap → stage 1 contributes 200.
	// Bytes 25–63: zero → stage 2 contributes 0; running total still 200.
	// Bytes 64–127: zero → stage 3 contributes 0; running total still 200.
	// Bytes 128–255: overlap → stage 4 would contribute 1024 if reached.
	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 0; i < 25; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}
	for i := 128; i < 256; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(1224), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 1224 (25 + 128 bytes * 8 bits)")

	// Stage 1 check: 8*200 + 48 = 1648 ≥ 600 → continue.
	// Stage 2 check: 4*200 + 48 = 848 ≥ 600 → continue.
	// Stage 3 check: 2*200 + 48 = 448 < 600 → return 0.
	got := andPopcountCut(bf1, bf2, 600, 48)
	checkEqual(t, uint32(0), got,
		"stage 3 early-exit must return 0 when 2*count + slack < cutOff")
}

// ---------------------------------------------------------------------------
// 00060000  No early-exit runs to completion
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_NoEarlyExit verifies that when the running count
// stays comfortably above the cutoff at every stage check, the function
// runs all four stages and returns the exact same count as andPopcount.
func TestRef_AndPopcountCut_NoEarlyExit(t *testing.T) {
	t.Parallel()

	// Bytes 0–127: overlap. Each stage check sees a count well above
	// any reasonable cutoff plus slack.
	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 0; i < 128; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(1024), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 1024 (128 bytes * 8 bits)")

	got := andPopcountCut(bf1, bf2, 100, 48)
	checkEqual(t, uint32(1024), got,
		"no early-exit must return the full count (matches andPopcount)")
}

// ---------------------------------------------------------------------------
// 00070000  CutOff zero disables early-exit
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_CutOffZero verifies that the `cutOff > 0` guard at
// each stage check disables short-circuiting when cutOff is 0. The same
// filter pair that triggers stage-1 short-circuit at cutOff=100 must run
// through to stage 4 at cutOff=0.
func TestRef_AndPopcountCut_CutOffZero(t *testing.T) {
	t.Parallel()

	// Stages 1–3 see count=0; stage 4 sees count=1024.
	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 128; i < 256; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	// With cutOff=0, every stage check has `cutOff > 0` false, so all
	// short-circuits are disabled. The function runs to stage 4.
	got := andPopcountCut(bf1, bf2, 0, 48)
	checkEqual(t, uint32(1024), got,
		"cutOff=0 must disable early-exit and return the full count")

	// Sanity: with cutOff>0 on the same filters, stage 1 fires.
	got = andPopcountCut(bf1, bf2, 100, 48)
	checkEqual(t, uint32(0), got,
		"sanity: cutOff>0 with the same filters must trigger stage 1 early-exit")
}

// ---------------------------------------------------------------------------
// 00080000  Slack parameter behavior
// ---------------------------------------------------------------------------

// TestRef_AndPopcountCut_SlackAbsorbs verifies that the slack parameter
// raises the bar at each stage check: a low slack triggers early-exit at
// stage 1; a slack large enough to span the gap to cutOff lets the function
// proceed to stage 4 and return the full count.
func TestRef_AndPopcountCut_SlackAbsorbs(t *testing.T) {
	t.Parallel()

	// Bytes 0–15: overlap → stages 1+ see count = 128 immediately.
	bf1 := make([]byte, 256)
	bf2 := make([]byte, 256)
	for i := 0; i < 16; i++ {
		bf1[i] = 0xff
		bf2[i] = 0xff
	}

	checkEqual(t, uint32(128), andPopcount(bf1, bf2),
		"sanity: andPopcount baseline must be 128 (16 bytes * 8 bits)")

	// With slack=48 and cutOff=2000:
	//   Stage 1 check: 8*128 + 48 = 1072 < 2000 → return 0.
	got := andPopcountCut(bf1, bf2, 2000, 48)
	checkEqual(t, uint32(0), got,
		"low slack with high cutOff must trigger stage 1 early-exit")

	// With slack=2000 and cutOff=2000:
	//   Stage 1 check: 8*128 + 2000 = 3024 ≥ 2000 → continue.
	//   Stage 2 check: 4*128 + 2000 = 2512 ≥ 2000 → continue.
	//   Stage 3 check: 2*128 + 2000 = 2256 ≥ 2000 → continue.
	//   Stage 4 returns 128.
	got = andPopcountCut(bf1, bf2, 2000, 2000)
	checkEqual(t, uint32(128), got,
		"high slack must absorb the gap and prevent early-exit")
}

// =========================================================================
// II. score_ref.go (sdbfScoreRef, sdbfMaxScoreRef)
// =========================================================================

// ---------------------------------------------------------------------------
// 00090000  sdbfScoreRef zero bfCount returns -1
// ---------------------------------------------------------------------------

// TestRef_ScoreRef_ZeroBfCount verifies the `bfCount1 == 0` guard in
// sdbfScoreRef. A digest with zero filters cannot be scored against
// anything, so the function returns -1 directly.
func TestRef_ScoreRef_ZeroBfCount(t *testing.T) {
	t.Parallel()

	emptyStream := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:0:0:\n"
	sd, err := ParseSdbfFromString(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	checkEqual(t, uint32(0), sd.FilterCount(), "sanity: FilterCount must be 0")

	inner := sd.(*sdbf)
	checkEqual(t, -1, sdbfScoreRef(inner, inner),
		"sdbfScoreRef must return -1 when bfCount is 0")
}

// ---------------------------------------------------------------------------
// 00100000  sdbfScoreRef both digests fully sparse returns -1
// ---------------------------------------------------------------------------

// TestRef_ScoreRef_DenominatorZero verifies the denominator==0 path in
// sdbfScoreRef. Constructing a 2-filter DD digest with both filters at
// elemCount=0 (below minElemCount=16) makes sparseCount equal to bfCount,
// so denominator goes to 0; the C++-faithful path explicitly resets
// scoreSum to -1 in that case before the negative-check returns -1.
func TestRef_ScoreRef_DenominatorZero(t *testing.T) {
	t.Parallel()

	b64 := func() string {
		// 256 zero bytes encoded once; reused for both filters.
		// base64.StdEncoding.EncodedLen(256) == 344: 85 full groups (340 chars) + 1-byte remainder ("AA==").
		return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	}()

	ddStr := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" +
		b64 + ":00:" + b64 + "\n"

	sd, err := ParseSdbfFromString(ddStr)
	mustNoError(t, err, "parsing a 2-filter DD digest with zero elem counts must succeed")

	checkEqual(t, uint32(2), sd.FilterCount(), "sanity: FilterCount must be 2")
	inner := sd.(*sdbf)
	checkEqual(t, -1, sdbfScoreRef(inner, inner),
		"sdbfScoreRef must return -1 when all filters are sparse and bfCount > 1")
}

// ---------------------------------------------------------------------------
// 00110000  sdbfMaxScoreRef sparse source returns 0
// ---------------------------------------------------------------------------

// TestRef_MaxScoreRef_SparseSource verifies the sparse-source guard
// (s1 < minElemCount → return 0) in sdbfMaxScoreRef. With the source
// filter's element count below minElemCount, the function must return 0
// without inspecting the target filter at all.
func TestRef_MaxScoreRef_SparseSource(t *testing.T) {
	t.Parallel()

	src := &sdbf{
		bfSize:     bfSize,
		bfCount:    1,
		buffer:     make([]byte, bfSize),
		elemCounts: []uint16{1}, // 1 < minElemCount=16 → sparse
		hamming:    []uint16{0},
	}
	// Empty target: sparse-source guard returns before touching this.
	target := &sdbf{
		bfSize:  bfSize,
		bfCount: 0,
	}

	got := sdbfMaxScoreRef(src, 0, target)
	checkEqual(t, float64(0), got,
		"sdbfMaxScoreRef must return 0 when source filter is sparse")
}

// ---------------------------------------------------------------------------
// 00120000  sdbfMaxScoreRef no scoreable target returns -1
// ---------------------------------------------------------------------------

// TestRef_MaxScoreRef_NoScoreableTarget verifies the sentinel -1 return
// path in sdbfMaxScoreRef. With a non-sparse source but every target
// filter sparse (s2 < minElemCount), the inner loop's `continue` skips
// every iteration and maxScore retains its initial -1.
func TestRef_MaxScoreRef_NoScoreableTarget(t *testing.T) {
	t.Parallel()

	// Real source: a high-entropy digest gives us a real bloom filter at
	// index 0 with elemCount well above minElemCount.
	src := streamDigest(t, randomBuf(1<<20, 1, 1)).(*sdbf)
	checkAtLeast(t, src.elemCount(0), uint32(minElemCount),
		"sanity: source filter must be non-sparse")

	// Synthetic target: every filter sparse.
	target := &sdbf{
		bfSize:     bfSize,
		bfCount:    2,
		buffer:     make([]byte, 2*bfSize),
		elemCounts: []uint16{1, 1}, // both sparse
		hamming:    []uint16{0, 0},
	}

	got := sdbfMaxScoreRef(src, 0, target)
	checkEqual(t, float64(-1), got,
		"sdbfMaxScoreRef must return -1 when every target filter is sparse")
}

// =========================================================================
// III. Sdbf.CompareRef
// =========================================================================

// ---------------------------------------------------------------------------
// 00130000  CompareRef nil other returns -1
// ---------------------------------------------------------------------------

// TestRef_CompareRef_NilOther verifies that CompareRef returns the
// degenerate sentinel -1 (rather than panicking) when the other argument
// is the nil Sdbf interface value.
func TestRef_CompareRef_NilOther(t *testing.T) {
	t.Parallel()

	sd := streamDigest(t, randomBuf(1<<20, 2, 2))
	checkEqual(t, -1, sd.CompareRef(nil),
		"CompareRef with a nil other must return -1")
}

// ---------------------------------------------------------------------------
// 00140000  CompareRef foreign Sdbf returns -1
// ---------------------------------------------------------------------------

// TestRef_CompareRef_ForeignOther verifies that CompareRef on a foreign
// Sdbf implementation (one that satisfies the interface but is not the
// internal *sdbf type) returns -1 rather than panicking on the type
// assertion. Mirrors TestIssue17_CompareForeignImpl for the modern Compare.
func TestRef_CompareRef_ForeignOther(t *testing.T) {
	t.Parallel()

	sd := streamDigest(t, randomBuf(1<<20, 3, 3))
	foreign := &foreignSdbfImpl{}

	var got int
	checkNotPanics(t, func() { got = sd.CompareRef(foreign) },
		"CompareRef on a foreign Sdbf must not panic")
	checkEqual(t, -1, got,
		"CompareRef on a foreign Sdbf must return -1")
}

// ---------------------------------------------------------------------------
// 00150000  CompareRef self-compare returns 100
// ---------------------------------------------------------------------------

// TestRef_CompareRef_SelfCompare verifies that a high-entropy digest
// compared with itself through the reference path returns 100. This is
// the most basic correctness check on the reference scoring pipeline.
func TestRef_CompareRef_SelfCompare(t *testing.T) {
	t.Parallel()

	sd := streamDigest(t, randomBuf(1<<20, 4, 4))
	checkEqual(t, 100, sd.CompareRef(sd),
		"CompareRef on a high-entropy self-compare must return 100")
}

// ---------------------------------------------------------------------------
// 00160000  CompareRef returns valid score on random pair
// ---------------------------------------------------------------------------

// TestRef_CompareRef_RandomPair is a smoke test that CompareRef on two
// independent high-entropy buffers returns an integer in [0, 100] (or -1
// for a degenerate comparison) without panicking.
func TestRef_CompareRef_RandomPair(t *testing.T) {
	t.Parallel()

	sdA := streamDigest(t, randomBuf(1<<20, 5, 5))
	sdB := streamDigest(t, randomBuf(1<<20, 6, 6))

	got := sdA.CompareRef(sdB)
	checkAtLeast(t, got, -1, "CompareRef result must be ≥ -1")
	checkAtMost(t, got, 100, "CompareRef result must be ≤ 100")
}
