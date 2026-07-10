package sdhash

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
)

// Test index
//
// I. General
// ├── 00010000  Error cases for New
// ├── 00020000  Stream mode basic properties
// ├── 00030000  Stream mode self-comparison
// ├── 00040000  DD mode basic properties
// ├── 00050000  DD mode self-comparison
// ├── 00060000  Round-trip stream
// ├── 00070000  Round-trip DD
// ├── 00080000  Cross-mode comparison
// ├── 00090000  Dissimilar data scores low
// ├── 00100000  Similar data scores high
// ├── 00110000  Concurrent compute
// └── 00120000  Concurrent compare
//
// II. bloom.go
// ├── 00130000  newBloomFilter invalid size
// └── 00140000  mustNewBloomFilter panic
//
// III. entropy.go
// ├── 00150000  entropy64Update clamp to zero
// └── 00160000  entropy64Update clamp to entropyScale
//
// IV. generate.go + score.go
// ├── 00170000  sdbfScore zero bfCount
// ├── 00180000  sdbfScore denominator zero
// ├── 00190000  sdbfScore source with no scoreable target
// ├── 00200000  generateChunkSdbf multi-chunk parallel
// ├── 00210000  generateChunkSdbf chunk size too small
// ├── 00220000  generateChunkSdbf exactly one chunk
// ├── 00230000  generateChunkSdbf multi-chunk sparse last filter
// ├── 00240000  generateChunkSdbf goroutine panic recovery
// ├── 00250000  generateBlockSdbf goroutine panic recovery
// └── 00260000  generateSingleBlockSdbf zero-threshold k clamp
//
// V. sdhash.go
// ├── 00270000  Parse error cases
// ├── 00280000  Parse stream without trailing newline
// ├── 00290000  FeatureDensity zero-filled
// ├── 00300000  FeatureDensity high entropy
// ├── 00310000  FeatureDensity DD mode
// ├── 00320000  FeatureDensity parsed digest
// ├── 00330000  FeatureDensity zero origFileSize
// ├── 00340000  ParseReader multiple digests
// ├── 00350000  Parse stream with Windows line ending
// └── 00360000  Parse DD with Windows line ending
//
// VI. factory.go
// ├── 00370000  populateSdbf stream mode error propagation
// ├── 00380000  populateSdbf block mode error propagation
// └── 00390000  populateSdbf block mode allocation cap

// =========================================================================
// I. General
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Error cases for New
// ---------------------------------------------------------------------------

func TestNew_EmptyBuffer(t *testing.T) {
	t.Parallel()
	_, err := New([]byte{})
	checkError(t, err, "empty buffer must return an error")
}

func TestNew_TooSmall(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MinFileSize-1)
	_, err := New(buf)
	checkError(t, err, "buffer smaller than MinFileSize must return an error")
}

func TestNew_ExactlyMinFileSize(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MinFileSize)
	_, err := New(buf)
	checkNoError(t, err, "buffer of exactly MinFileSize must succeed")
}

// ---------------------------------------------------------------------------
// 00020000  Stream mode basic properties
// ---------------------------------------------------------------------------

func TestStreamMode_BasicProperties(t *testing.T) {
	t.Parallel()
	const size = 1 << 20 // 1 MiB
	buf := randomBuf(size, 1, 1)
	sd := streamDigest(t, buf)

	checkNotNil(t, sd, "stream digest must not be nil")
	checkEqual(t, uint64(size), sd.InputSize(), "InputSize should match buffer length")
	checkGreater(t, sd.FilterCount(), uint32(0), "FilterCount should be > 0")
	checkEqual(t, uint64(sd.FilterCount())*256, sd.FilterSize(), "FilterSize should equal FilterCount * 256")
	checkTrue(t, strings.HasPrefix(sd.String(), "sdbf:03:1:-:"), "String should start with stream prefix")
	checkTrue(t, strings.HasSuffix(sd.String(), "\n"), "String should end with newline")
}

// ---------------------------------------------------------------------------
// 00030000  Stream mode self-comparison
// ---------------------------------------------------------------------------

func TestStreamMode_SelfComparison(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := streamDigest(t, buf)
	score, ok := sd.Similarity(sd)
	checkTrue(t, ok, "self-comparison must be comparable")
	checkEqual(t, 100, score, "self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 00040000  DD mode basic properties
// ---------------------------------------------------------------------------

func TestDDMode_BasicProperties(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := ddDigest(t, buf, 1024)

	checkNotNil(t, sd, "DD digest must not be nil")
	checkTrue(t, strings.HasPrefix(sd.String(), "sdbf-dd:03:1:-:"), "String should start with DD prefix")
}

// ---------------------------------------------------------------------------
// 00050000  DD mode self-comparison
// ---------------------------------------------------------------------------

func TestDDMode_SelfComparison(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := ddDigest(t, buf, 1024)
	score, ok := sd.Similarity(sd)
	checkTrue(t, ok, "DD self-comparison must be comparable")
	checkEqual(t, 100, score, "DD self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 00060000  Round-trip stream
// ---------------------------------------------------------------------------

func TestRoundTrip_Stream(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	original := streamDigest(t, buf)

	parsed, err := Parse(original.String())
	mustNoError(t, err, "Parse must succeed on a valid stream digest string")

	checkEqual(t, original.String(), parsed.String(), "round-tripped string must be identical")
	score, ok := parsed.Similarity(original)
	checkTrue(t, ok, "round-tripped digest must be comparable")
	checkEqual(t, 100, score, "round-tripped digest must score 100 against original")
}

// ---------------------------------------------------------------------------
// 00070000  Round-trip DD
// ---------------------------------------------------------------------------

func TestRoundTrip_DD(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	original := ddDigest(t, buf, 1024)

	parsed, err := Parse(original.String())
	mustNoError(t, err, "Parse must succeed on a valid DD digest string")

	checkEqual(t, original.String(), parsed.String(), "round-tripped string must be identical")
	score, ok := parsed.Similarity(original)
	checkTrue(t, ok, "round-tripped digest must be comparable")
	checkEqual(t, 100, score, "round-tripped digest must score 100 against original")
}

// ---------------------------------------------------------------------------
// 00080000  Cross-mode comparison
// ---------------------------------------------------------------------------

func TestCrossMode_DoesNotPanic(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	stream := streamDigest(t, buf)
	dd := ddDigest(t, buf, 1024)

	var score int
	var ok bool
	checkNotPanics(t, func() { score, ok = stream.Similarity(dd) }, "cross-mode Similarity must not panic")
	checkTrue(t, ok, "cross-mode Similarity must be meaningful")
	checkAtLeast(t, score, 0, "cross-mode score must be >= 0")
	checkAtMost(t, score, 100, "cross-mode score must be <= 100")
}

// ---------------------------------------------------------------------------
// 00090000  Dissimilar data scores low
// ---------------------------------------------------------------------------

func TestDissimilarData_ScoresLow(t *testing.T) {
	t.Parallel()
	buf1 := randomBuf(1<<20, 1, 1)
	buf2 := randomBuf(1<<20, 2, 2) // different seed → different data
	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	// sdhash can return 1 on fully dissimilar random data due to floating-point
	// rounding in the final score calculation. The important invariant is that the
	// score is very low (effectively 0), not that it is exactly 0.
	score, ok := sd1.Similarity(sd2)
	checkTrue(t, ok, "dissimilar data must be comparable")
	checkAtMost(t, score, 1, "dissimilar buffers must score 0 or 1")
}

// ---------------------------------------------------------------------------
// 00100000  Similar data scores high
// ---------------------------------------------------------------------------

func TestSimilarData_ScoresHigh(t *testing.T) {
	t.Parallel()
	const size = 1 << 20
	buf1 := randomBuf(size, 1, 1)

	// Flip ~0.1% of bytes (roughly 1024 of 1 MiB).
	buf2 := make([]byte, size)
	copy(buf2, buf1)
	flipRng := rand.New(rand.NewPCG(99, 99))
	flips := size / 1000
	for range flips {
		idx := int(flipRng.Uint64() % uint64(size))
		buf2[idx] ^= 0xFF
	}

	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	score, ok := sd1.Similarity(sd2)
	checkTrue(t, ok, "similar data must be comparable")
	checkGreater(t, score, 0, "lightly modified buffer must score > 0")
}

// ---------------------------------------------------------------------------
// 00110000  Concurrent compute
// ---------------------------------------------------------------------------

func TestConcurrent_ComputeMultiple(t *testing.T) {
	t.Parallel()
	const goroutines = 10
	results := make([]Digest, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			buf := randomBuf(1<<20, uint64(idx+10), uint64(idx+20))
			factory, err := New(buf)
			if err != nil {
				errs[idx] = err
				return
			}
			sd, err := factory.Compute()
			errs[idx] = err
			results[idx] = sd
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		checkNoError(t, err, fmt.Sprintf("goroutine %d must not error", i))
		if results[i] == nil {
			t.Errorf("goroutine %d must produce a non-nil digest", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 00120000  Concurrent compare
// ---------------------------------------------------------------------------

func TestConcurrent_Similarity(t *testing.T) {
	t.Parallel()
	buf1 := randomBuf(1<<20, 1, 1)
	buf2 := randomBuf(1<<20, 1, 1) // same seed → same data → score 100
	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	expected, ok := sd1.Similarity(sd2)
	checkTrue(t, ok, "initial comparison must be comparable")

	const goroutines = 20
	scores := make([]int, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scores[idx], _ = sd1.Similarity(sd2)
		}(i)
	}
	wg.Wait()

	for i, score := range scores {
		checkEqual(t, expected, score,
			fmt.Sprintf("concurrent Similarity result must be consistent (goroutine %d)", i))
	}
}

// =========================================================================
// II. bloom.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00130000  newBloomFilter invalid size
// ---------------------------------------------------------------------------

func TestNewBloomFilter_InvalidSize(t *testing.T) {
	t.Parallel()

	_, err := newBloomFilter(32, defaultHashCount, 100)
	checkError(t, err, "size 32 (< 64) must return an error")

	_, err = newBloomFilter(0, defaultHashCount, 100)
	checkError(t, err, "size 0 must return an error")

	_, err = newBloomFilter(100, defaultHashCount, 100)
	checkError(t, err, "size 100 (not a power of 2) must return an error")

	bf, err := newBloomFilter(64, defaultHashCount, 100)
	checkNoError(t, err, "size 64 must succeed")
	if bf == nil {
		t.Errorf("size 64: expected non-nil bloom filter, got nil")
	} else {
		checkLen(t, bf.buffer, 64, "size 64: bloom filter buffer length")
	}
}

// ---------------------------------------------------------------------------
// 00140000  mustNewBloomFilter panic
// ---------------------------------------------------------------------------

// TestMustNewBloomFilter_PanicsOnInvalidSize verifies that mustNewBloomFilter
// panics when given a size that newBloomFilter rejects. In production code,
// mustNewBloomFilter is only ever called with the compile-time constant
// bigFilter=16384, so this panic is unreachable at runtime — but the branch
// must be tested to confirm the panic contract is correctly implemented.
func TestMustNewBloomFilter_PanicsOnInvalidSize(t *testing.T) {
	t.Parallel()
	checkPanics(t,
		func() { mustNewBloomFilter(100, defaultHashCount, 100) },
		"mustNewBloomFilter with an invalid size must panic",
	)
}

// =========================================================================
// III. entropy.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00150000  entropy64Update clamp to zero
// ---------------------------------------------------------------------------

// TestEntropy64IncInt_ClampToZero exercises the path where the incremental
// entropy update would produce a negative int64 value and is clamped to 0.
//
// Construction: prevEntropy=0, remove a character that appears once in the
// window (large positive oldDiff), add to a character that appears 50 times
// (negative newDiff because entropy64Int is decreasing above its peak near
// count=23). The combined effect is 0 - large_positive - something = negative.
func TestEntropy64IncInt_ClampToZero(t *testing.T) {
	t.Parallel()

	ascii := make([]uint8, 256)
	ascii['A'] = 1
	ascii['B'] = 50

	buf := make([]uint8, 65)
	buf[0] = 'A'
	buf[64] = 'B'

	result := entropy64Update(0, buf, ascii)
	checkEqual(t, uint64(0), result,
		"entropy calculation going negative must be clamped to 0")
}

// ---------------------------------------------------------------------------
// 00160000  entropy64Update clamp to entropyScale
// ---------------------------------------------------------------------------

// TestEntropy64IncInt_ClampToEntropyScale exercises the path where the
// incremental update would exceed entropyScale and is clamped.
//
// Construction: prevEntropy=entropyScale (maximum), remove a character that
// appears 50 times (oldDiff is negative — subtracting a negative value adds to
// entropy), add to a character that appears once (newDiff is large positive).
// The combined effect overshoots entropyScale.
func TestEntropy64IncInt_ClampToEntropyScale(t *testing.T) {
	t.Parallel()

	ascii := make([]uint8, 256)
	ascii['A'] = 50
	ascii['B'] = 1

	buf := make([]uint8, 65)
	buf[0] = 'A'
	buf[64] = 'B'

	result := entropy64Update(uint64(entropyScale), buf, ascii)
	checkEqual(t, uint64(entropyScale), result,
		"entropy calculation exceeding entropyScale must be clamped to entropyScale")
}

// =========================================================================
// IV. generate.go + score.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00170000  sdbfScore zero bfCount
// ---------------------------------------------------------------------------

// TestSdbfScore_ZeroBfCount verifies that comparing a digest that has no bloom
// filters returns -1. This exercises the bfCount1==0 guard in sdbfScore.
func TestSdbfScore_ZeroBfCount(t *testing.T) {
	t.Parallel()

	emptyStream := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:0:0:\n"
	sd, err := Parse(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	checkEqual(t, uint32(0), sd.FilterCount(), "FilterCount must be 0")
	_, ok := sd.Similarity(sd)
	checkTrue(t, !ok,
		"Similarity on a zero-filter digest must not be comparable")
}

// ---------------------------------------------------------------------------
// 00180000  sdbfScore denominator zero
// ---------------------------------------------------------------------------

// TestSdbfScore_DenominatorZero verifies the denominator==0 guard in sdbfScore.
// The guard fires when bfCount1 > 1 and every filter has an element count below
// minElemCount (16), so sparseCount == bfCount1 and denominator = 0.
func TestSdbfScore_DenominatorZero(t *testing.T) {
	t.Parallel()

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	ddStr := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" +
		b64 + ":00:" + b64 + "\n"

	sd, err := Parse(ddStr)
	mustNoError(t, err, "parsing a 2-filter DD digest with zero elem counts must succeed")

	checkEqual(t, uint32(2), sd.FilterCount(), "FilterCount must be 2")
	inner := sd.(*sdbf)
	checkEqual(t, -1, sdbfScore(inner, inner),
		"sdbfScore with all-sparse filters and bfCount>1 must return -1 (denominator=0 path)")
}

// ---------------------------------------------------------------------------
// 00190000  sdbfScore source with no scoreable target
// ---------------------------------------------------------------------------

// TestSdbfScore_NoScoreableTarget exercises the s < 0 branch in sdbfScore's
// accumulation loop, where a source filter has enough elements to be scored but
// no target filter does. In that case sdbfMaxScore returns -1 and the filter is
// excluded via noTargetCount (as opposed to the sparseCount path covered by
// TestSdbfScore_DenominatorZero). The source is a single filter with 32 elements;
// the target has two filters that are both too sparse (element count 0 <
// minElemCount), so the lone source-filter lookup finds no scoreable target.
// With the only source filter excluded the denominator is zero, so the
// comparison is reported as not meaningful. Two target filters are used so the
// equal-count tiebreaker does not swap the operands.
func TestSdbfScore_NoScoreableTarget(t *testing.T) {
	t.Parallel()

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	// Source: one filter with element count 0x20 (32 ≥ minElemCount).
	src := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:20:" + b64 + "\n"
	// Target: two filters, both element count 0 (< minElemCount) → all sparse.
	tgt := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" + b64 + ":00:" + b64 + "\n"

	srcSd, err := Parse(src)
	mustNoError(t, err, "parsing the single-filter source digest must succeed")
	tgtSd, err := Parse(tgt)
	mustNoError(t, err, "parsing the all-sparse target digest must succeed")

	checkEqual(t, uint32(1), srcSd.FilterCount(), "source must have one filter")
	checkEqual(t, uint32(2), tgtSd.FilterCount(), "target must have two filters")

	_, ok := srcSd.Similarity(tgtSd)
	checkTrue(t, !ok,
		"a source filter whose only candidates are all too sparse must yield no meaningful comparison (noTargetCount path)")
}

// ---------------------------------------------------------------------------
// 00200000  generateChunkSdbf multi-chunk parallel
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_MultiChunk exercises the parallel goroutine phase by
// calling generateChunkSdbf directly with a 1 MiB chunk size and a 3.5 MiB
// buffer. That gives qt=3, rem=0.5 MiB, totalChunks=4, which is enough to
// drive the semaphore pool and both the loop goroutines and the rem goroutine.
func TestGenerateChunkSdbf_MultiChunk(t *testing.T) {
	t.Parallel()

	const chunkSize = 1 << 20
	const totalSize = 3*chunkSize + chunkSize/2

	buf := randomBuf(totalSize, 7, 7)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(totalSize)

	mustNoError(t, sd.generateChunkSdbf(buf, chunkSize), "generateChunkSdbf must not error on valid input")
	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "multi-chunk digest must have at least one filter")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize after trim")
	checkLen(t, sd.hamming, int(sd.bfCount),
		"hamming slice length must equal bfCount")
	checkEqual(t, 100, sdbfScore(sd, sd), "multi-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00210000  generateChunkSdbf chunk size too small
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_ChunkSizeTooSmall verifies that generateChunkSdbf
// returns an error when chunkSize is not strictly greater than popWinSize.
func TestGenerateChunkSdbf_ChunkSizeTooSmall(t *testing.T) {
	t.Parallel()

	buf := randomBuf(MinFileSize, 8, 8)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(MinFileSize)

	err := sd.generateChunkSdbf(buf, uint64(popWinSize))
	checkError(t, err, "chunkSize <= popWinSize must return an error")
}

// ---------------------------------------------------------------------------
// 00220000  generateChunkSdbf exactly one chunk
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_ExactlyOneChunk exercises the qt==1 branch inside the
// single-chunk fast path. It fires when fileSize == chunkSize exactly
// (qt=1, rem=0, totalChunks=1).
func TestGenerateChunkSdbf_ExactlyOneChunk(t *testing.T) {
	t.Parallel()

	const size = 1 << 19 // 512 KiB
	buf := randomBuf(size, 42, 42)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(size)

	mustNoError(t, sd.generateChunkSdbf(buf, size), "generateChunkSdbf must not error on valid input")
	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "exactly-one-chunk digest must have at least one filter")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize")
	checkEqual(t, 100, sdbfScore(sd, sd),
		"exactly-one-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00230000  generateChunkSdbf multi-chunk sparse last filter
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_MultiChunk_SparseLastFilter exercises the "drop last
// sparse filter" condition in the multi-chunk path.
//
// Construction: chunkSize = 10 KiB, fileSize = 20 KiB (qt=2, rem=0 →
// multi-chunk path). With seed=1 and 10 KiB of random data, the first chunk
// produces exactly enough unique features to fill one complete filter
// (bfCount → 2, lastCount → 0). The all-zeros second chunk adds 0 features.
// The pruning condition fires, decrementing bfCount back to 1 and setting
// lastCount = maxElem. These values were confirmed empirically.
func TestGenerateChunkSdbf_MultiChunk_SparseLastFilter(t *testing.T) {
	t.Parallel()

	const chunkSize = 10240
	buf := make([]byte, 2*chunkSize)
	copy(buf[:chunkSize], randomBuf(chunkSize, 1, 1))

	sd := newTestSdbf(t)
	sd.origFileSize = uint64(len(buf))

	mustNoError(t, sd.generateChunkSdbf(buf, chunkSize), "generateChunkSdbf must not error on valid input")
	sd.computeHamming()

	checkEqual(t, uint32(1), sd.bfCount,
		"bfCount must be 1 after sparse-filter pruning decrements it from 2")
	checkEqual(t, sd.maxElem, sd.lastCount,
		"lastCount must equal maxElem after pruning resets it")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize after pruning and trim")
	checkEqual(t, 100, sdbfScore(sd, sd),
		"pruned multi-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00240000  generateChunkSdbf goroutine panic recovery
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_GoroutinePanicRecovery verifies that a panic inside a
// generateChunkSdbf goroutine is recovered and returned as an error rather than
// terminating the process.
//
// Construction: sd.testFaultHook is set so that generateChunkRanks, called
// inside each Phase 1 goroutine, panics on entry, exercising the goroutine
// recover path. A 4 MiB buffer with a 1 MiB chunk size
// produces qt=4, exercising the parallel goroutine pool and recover path.
func TestGenerateChunkSdbf_GoroutinePanicRecovery(t *testing.T) {
	t.Parallel()

	const chunkSize = 1 << 20
	buf := randomBuf(4*chunkSize, 100, 100)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(len(buf))
	sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }

	var err error
	checkNotPanics(t,
		func() { err = sd.generateChunkSdbf(buf, chunkSize) },
		"generateChunkSdbf must not propagate a goroutine panic to the caller",
	)
	checkError(t, err, "generateChunkSdbf must return an error when a goroutine panics")
}

// ---------------------------------------------------------------------------
// 00250000  generateBlockSdbf goroutine panic recovery
// ---------------------------------------------------------------------------

// TestGenerateBlockSdbf_GoroutinePanicRecovery verifies that a panic inside a
// generateBlockSdbf goroutine is recovered and returned as an error rather than
// terminating the process.
//
// Construction: sd.buffer and sd.elemCounts are left nil so that
// generateSingleBlockSdbf → generateBlockHash panics when it indexes into
// sd.buffer. A 1 MiB buffer with a 1 KiB block size produces many parallel
// blocks, ensuring the goroutine pool and recover path are exercised.
func TestGenerateBlockSdbf_GoroutinePanicRecovery(t *testing.T) {
	t.Parallel()

	const blockSize = 1024
	buf := randomBuf(1<<20, 101, 101)
	sd := newTestSdbf(t)
	sd.ddBlockSize = blockSize
	sd.maxElem = maxElemDd
	sd.origFileSize = uint64(len(buf))
	// sd.buffer and sd.elemCounts intentionally left nil to force a panic
	// inside generateSingleBlockSdbf when it calls generateBlockHash.

	var err error
	checkNotPanics(t,
		func() { err = sd.generateBlockSdbf(buf) },
		"generateBlockSdbf must not propagate a goroutine panic to the caller",
	)
	checkError(t, err, "generateBlockSdbf must return an error when a goroutine panics")
}

// ---------------------------------------------------------------------------
// 00260000  generateSingleBlockSdbf zero-threshold k clamp
// ---------------------------------------------------------------------------

// TestGenerateSingleBlockSdbf_ZeroThresholdClamp verifies that
// generateSingleBlockSdbf does not panic when threshold is 0, and that k is
// clamped to 0 rather than left at -1 before being converted back to a
// uint32 argument for generateBlockHash.
//
// threshold is always the package constant 16 in production; this exercises
// defensive hardening for a value that is not currently reachable.
//
// Construction: a 128-byte block (2x popWinSize) keeps the total number of
// scored windows (blockSize - popWinSize = 64) comfortably under maxElemDd
// (192), so the sum-vs-maxElem break in the k loop never fires and the loop
// runs all the way down to -1, guaranteeing the clamp branch executes.
func TestGenerateSingleBlockSdbf_ZeroThresholdClamp(t *testing.T) {
	t.Parallel()

	const ddBlockSize = 128
	sd := newTestSdbf(t)
	sd.ddBlockSize = ddBlockSize
	sd.maxElem = maxElemDd
	sd.threshold = 0
	sd.buffer = make([]byte, uint64(sd.bfCount)*uint64(sd.bfSize))
	sd.elemCounts = make([]uint16, sd.bfCount)

	fileBuffer := randomBuf(ddBlockSize, 102, 102)

	checkNotPanics(t,
		func() { sd.generateSingleBlockSdbf(fileBuffer, 0) },
		"generateSingleBlockSdbf must not panic when threshold is 0",
	)
}

// =========================================================================
// V. sdhash.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00270000  Parse error cases
// ---------------------------------------------------------------------------

func TestParse_ErrorCases(t *testing.T) {
	t.Parallel()

	validB64 := base64.StdEncoding.EncodeToString(make([]byte, 256))

	// A 257-byte block encodes to exactly base64.StdEncoding.EncodedLen(256)==344
	// characters (256, 257, and 258 bytes all encode to 344 chars), so it passes
	// the encoded-length check and decodes cleanly, but yields 257 bytes instead
	// of bfSize==256 — exercising the decoded-length mismatch branch.
	decodedLenMismatchB64 := base64.StdEncoding.EncodeToString(make([]byte, 257))

	cases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"truncated after magic colon", "sdbf:"},
		{"unsupported version", "sdbf:99:1:-:1048576:sha1:256:5:7ff:160:1:100:" + validB64 + "\n"},
		{"unrecognized magic", "badmagic:03:1:-:1048576:sha1:256:5:7ff:160:1:100:" + validB64 + "\n"},
		{"non-numeric file size", "sdbf:03:1:-:notanumber:sha1:256:5:7ff:160:1:100:" + validB64 + "\n"},
		{"non-numeric bfSize", "sdbf:03:1:-:1048576:sha1:notanumber:5:7ff:160:1:100:" + validB64 + "\n"},
		{"invalid base64 in stream buffer", "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:100:!!invalid!!\n"},
		{"truncated DD missing block size field", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:"},
		{"DD invalid hex elem count", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:zz:" + validB64 + "\n"},
		{"DD invalid base64 block data", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:!!invalid!!\n"},
		{"DD invalid base64 content correct length", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:" + strings.Repeat("!", 344) + "\n"},
		{"DD decoded block length mismatch", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:" + decodedLenMismatchB64 + "\n"},
		{"truncated after version", "sdbf:03:"},
		{"truncated after namelen", "sdbf:03:1:"},
		{"truncated after origFileSize", "sdbf:03:1:-:1048576:"},
		{"truncated after bfSize", "sdbf:03:1:-:1048576:sha1:256:"},
		{"truncated after hashCount", "sdbf:03:1:-:1048576:sha1:256:5:"},
		{"truncated after bitMask", "sdbf:03:1:-:1048576:sha1:256:5:7ff:"},
		{"truncated after maxElem", "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:"},
		{"stream truncated after bfCount", "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:"},
		{"DD readField fails on second filter", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" + validB64 + ":"},
		{"DD base64 decode fails on second filter", "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" + validB64 + ":c0:!!bad!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.input)
			checkError(t, err, fmt.Sprintf("expected an error for case %q", tc.name))
		})
	}
}

// ---------------------------------------------------------------------------
// 00280000  Parse stream without trailing newline
// ---------------------------------------------------------------------------

// TestParse_StreamWithoutTrailingNewline verifies that a digest string
// with the trailing '\n' stripped parses identically to the newline-terminated
// form.
func TestParse_StreamWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := streamDigest(t, buf)

	withoutNewline := strings.TrimRight(sd.String(), "\n")
	checkTrue(t, !strings.HasSuffix(withoutNewline, "\n"), "test string must not end with newline")

	parsed, err := Parse(withoutNewline)
	mustNoError(t, err, "Parse must succeed without trailing newline")
	checkEqual(t, sd.String(), parsed.String(),
		"digest parsed without trailing newline must be identical to original")
}

// ---------------------------------------------------------------------------
// 00290000  FeatureDensity zero-filled
// ---------------------------------------------------------------------------

// TestFeatureDensity_ZeroFilled verifies that a zero-filled buffer produces
// near-zero feature density.
func TestFeatureDensity_ZeroFilled(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 1<<20)
	sd := streamDigest(t, buf)
	density := sd.FeatureDensity()
	checkAtMost(t, density, 0.001,
		"zero-filled buffer must have near-zero feature density")
}

// ---------------------------------------------------------------------------
// 00300000  FeatureDensity high entropy
// ---------------------------------------------------------------------------

// TestFeatureDensity_HighEntropy verifies that a high-entropy random buffer
// produces feature density greater than 0.01.
func TestFeatureDensity_HighEntropy(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 7, 7)
	sd := streamDigest(t, buf)
	density := sd.FeatureDensity()
	checkGreater(t, density, 0.01,
		"high-entropy buffer must have feature density greater than 0.01")
}

// ---------------------------------------------------------------------------
// 00310000  FeatureDensity DD mode
// ---------------------------------------------------------------------------

// TestFeatureDensity_DDMode verifies that FeatureDensity works correctly in
// block-aligned mode by summing per-filter element counts.
func TestFeatureDensity_DDMode(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 7, 7)
	sd := ddDigest(t, buf, 65536)
	density := sd.FeatureDensity()
	checkGreater(t, density, 0.0,
		"DD-mode digest of random data must have positive feature density")
}

// ---------------------------------------------------------------------------
// 00320000  FeatureDensity parsed digest
// ---------------------------------------------------------------------------

// TestFeatureDensity_ParsedDigest verifies that FeatureDensity is correct on
// a digest reconstructed from its wire format string.
func TestFeatureDensity_ParsedDigest(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 3, 3)
	original := streamDigest(t, buf)
	parsed, err := Parse(original.String())
	mustNoError(t, err)
	checkEqual(t, original.FeatureDensity(), parsed.FeatureDensity(),
		"FeatureDensity must survive a round-trip through String/Parse")
}

// ---------------------------------------------------------------------------
// 00330000  FeatureDensity zero origFileSize
// ---------------------------------------------------------------------------

// TestFeatureDensity_ZeroOrigFileSize verifies that FeatureDensity returns 0
// when origFileSize is 0, exercising the early-return guard against division
// by zero.
func TestFeatureDensity_ZeroOrigFileSize(t *testing.T) {
	t.Parallel()

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	zeroSizeStream := "sdbf:03:1:-:0:sha1:256:5:7ff:160:1:42:" + b64 + "\n"

	sd, err := Parse(zeroSizeStream)
	mustNoError(t, err, "parsing a stream digest with origFileSize=0 must succeed")
	checkEqual(t, float64(0), sd.FeatureDensity(),
		"FeatureDensity must return 0 when origFileSize is 0")
}

// ---------------------------------------------------------------------------
// 00340000  ParseReader multiple digests
// ---------------------------------------------------------------------------

// TestParseReader_MultipleDigests verifies that ParseReader
// correctly parses multiple digests sequentially from a single reader, and
// returns an error once all digests have been consumed.
func TestParseReader_MultipleDigests(t *testing.T) {
	t.Parallel()
	buf1 := randomBuf(1<<20, 1, 1)
	buf2 := randomBuf(1<<20, 2, 2)
	buf3 := randomBuf(1<<20, 3, 3)
	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	sd3 := streamDigest(t, buf3)

	concatenated := sd1.String() + sd2.String() + sd3.String()
	r := bufio.NewReader(strings.NewReader(concatenated))

	parsed1, err := ParseReader(r)
	mustNoError(t, err, "first ParseReader must succeed")
	checkEqual(t, sd1.String(), parsed1.String(), "first parsed digest must match original")

	parsed2, err := ParseReader(r)
	mustNoError(t, err, "second ParseReader must succeed")
	checkEqual(t, sd2.String(), parsed2.String(), "second parsed digest must match original")

	parsed3, err := ParseReader(r)
	mustNoError(t, err, "third ParseReader must succeed")
	checkEqual(t, sd3.String(), parsed3.String(), "third parsed digest must match original")

	_, err = ParseReader(r)
	checkError(t, err, "fourth ParseReader must return an error at EOF")
}

// ---------------------------------------------------------------------------
// 00350000  Parse stream with Windows line ending
// ---------------------------------------------------------------------------

// TestParse_StreamWithWindowsLineEnding verifies that a stream digest
// string with a Windows-style '\r\n' line ending parses correctly and
// round-trips identically to the canonical '\n'-terminated form.
func TestParse_StreamWithWindowsLineEnding(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 95, 95)
	sd := streamDigest(t, buf)

	original := sd.String()
	withCRLF := strings.TrimRight(original, "\n") + "\r\n"

	parsed, err := Parse(withCRLF)
	mustNoError(t, err, "Parse must succeed with Windows line ending")
	checkEqual(t, original, parsed.String(),
		"digest parsed from Windows line ending must produce canonical newline output")

	score, ok := parsed.Similarity(parsed)
	checkTrue(t, ok, "self-comparison must be comparable")
	checkEqual(t, 100, score, "self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 00360000  Parse DD with Windows line ending
// ---------------------------------------------------------------------------

// TestParse_DDWithWindowsLineEnding verifies that a DD digest string
// with a Windows-style '\r\n' line ending parses correctly and round-trips
// identically to the canonical '\n'-terminated form.
func TestParse_DDWithWindowsLineEnding(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 96, 96)
	sd := ddDigest(t, buf, 65536)

	original := sd.String()
	withCRLF := strings.TrimRight(original, "\n") + "\r\n"

	parsed, err := Parse(withCRLF)
	mustNoError(t, err, "Parse must succeed with Windows line ending")
	checkEqual(t, original, parsed.String(),
		"digest parsed from Windows line ending must produce canonical newline output")

	score, ok := parsed.Similarity(parsed)
	checkTrue(t, ok, "self-comparison must be comparable")
	checkEqual(t, 100, score, "self-comparison must return 100")
}

// =========================================================================
// VI. factory.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00370000  populateSdbf stream mode error propagation
// ---------------------------------------------------------------------------

// TestPopulateSdbf_StreamModeErrorPropagation verifies that an error returned
// by generateChunkSdbf is propagated by populateSdbf rather than silently
// dropped.
//
// Construction: sd.testFaultHook is set so that generateChunkRanks, called
// inside each Phase 1 goroutine, panics on entry. The buffer must exceed the
// 32 MiB chunk size that
// populateSdbf passes to generateChunkSdbf; a smaller buffer produces
// totalChunks=1 and hits the single-chunk fast path, which runs
// generateChunkRanks directly in the calling goroutine with no recover in
// scope. 33 MiB gives qt=1 and a 1 MiB remainder (totalChunks=2), which is
// the minimum configuration that exercises the goroutine recover path.
func TestPopulateSdbf_StreamModeErrorPropagation(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 33<<20) // 33 MiB — must exceed the 32 MiB chunk size
	sd := newTestSdbf(t)
	sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }

	var err error
	checkNotPanics(t,
		func() { _, err = populateSdbf(sd, buf, 0) },
		"populateSdbf must not propagate a goroutine panic to the caller",
	)
	checkError(t, err, "populateSdbf must propagate an error from generateChunkSdbf")
}

// ---------------------------------------------------------------------------
// 00380000  populateSdbf block mode error propagation
// ---------------------------------------------------------------------------

// TestPopulateSdbf_BlockModeErrorPropagation verifies that an error returned
// by generateBlockSdbf is propagated by populateSdbf rather than silently
// dropped.
//
// Construction: sd.testFaultHook is set so that generateChunkRanks, called
// inside each block goroutine via generateSingleBlockSdbf, panics on entry.
// A buffer of 4×ddBlockSize produces
// qt=4 goroutines, exercising the parallel block path.
func TestPopulateSdbf_BlockModeErrorPropagation(t *testing.T) {
	t.Parallel()

	const ddBlockSize = 1024
	buf := randomBuf(4*ddBlockSize, 201, 201)
	sd := newTestSdbf(t)
	sd.testFaultHook = func() { panic("injected fault: generateChunkRanks") }

	var err error
	checkNotPanics(t,
		func() { _, err = populateSdbf(sd, buf, ddBlockSize) },
		"populateSdbf must not propagate a goroutine panic to the caller",
	)
	checkError(t, err, "populateSdbf must propagate an error from generateBlockSdbf")
}

// ---------------------------------------------------------------------------
// 00390000  populateSdbf block mode allocation cap
// ---------------------------------------------------------------------------

// TestPopulateSdbf_BlockModeAllocationCap verifies that populateSdbf rejects
// a DD-mode request whose bfCount would exceed maxBfAlloc/bfSize, before
// allocating sd.buffer or sd.elemCounts.
//
// Construction: ddBlockSize is fixed at the minimum legal value (popWinSize)
// to minimize the buffer needed to push bfCount past the cap. At bfSize=256
// and maxBfAlloc=256 MiB, the cap works out to maxBfAlloc/bfSize =
// 1,048,576 filters; a buffer of (filterCap+1)*popWinSize bytes yields
// exactly filterCap+1 filters with no remainder.
func TestPopulateSdbf_BlockModeAllocationCap(t *testing.T) {
	t.Parallel()

	const ddBlockSize = popWinSize
	filterCap := maxBfAlloc / bfSize
	buf := make([]byte, (filterCap+1)*ddBlockSize)
	sd := newTestSdbf(t)

	_, err := populateSdbf(sd, buf, ddBlockSize)
	checkError(t, err, "populateSdbf must reject a bfCount that exceeds maxBfAlloc/bfSize")
}
