package sdhash

import (
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
// ├── 00010000  Error cases for CreateSdbfFromBytes
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
// ├── 00150000  entropy64IncInt clamp to zero
// └── 00160000  entropy64IncInt clamp to entropyScale
//
// IV. generate.go + score.go
// ├── 00170000  sdbfScore zero bfCount
// ├── 00180000  sdbfScore denominator zero
// ├── 00190000  generateChunkSdbf multi-chunk parallel
// ├── 00200000  generateChunkSdbf chunk size too small
// ├── 00210000  generateChunkSdbf exactly one chunk
// └── 00220000  generateChunkSdbf multi-chunk sparse last filter
//
// V. sdhash.go
// ├── 00230000  ParseSdbfFromString error cases
// ├── 00240000  ParseSdbfFromString stream without trailing newline
// ├── 00250000  FeatureDensity zero-filled
// ├── 00260000  FeatureDensity high entropy
// ├── 00270000  FeatureDensity DD mode
// ├── 00280000  FeatureDensity parsed digest
// └── 00290000  FeatureDensity zero origFileSize

// =========================================================================
// I. General
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Error cases for CreateSdbfFromBytes
// ---------------------------------------------------------------------------

func TestCreateSdbfFromBytes_EmptyBuffer(t *testing.T) {
	t.Parallel()
	_, err := CreateSdbfFromBytes([]byte{})
	checkError(t, err, "empty buffer must return an error")
}

func TestCreateSdbfFromBytes_TooSmall(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MinFileSize-1)
	_, err := CreateSdbfFromBytes(buf)
	checkError(t, err, "buffer smaller than MinFileSize must return an error")
}

func TestCreateSdbfFromBytes_ExactlyMinFileSize(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MinFileSize)
	_, err := CreateSdbfFromBytes(buf)
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
	checkEqual(t, uint64(sd.FilterCount())*256, sd.Size(), "Size should equal FilterCount * 256")
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
	checkEqual(t, 100, sd.Compare(sd), "self-comparison must return 100")
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
	checkEqual(t, 100, sd.Compare(sd), "DD self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 00060000  Round-trip stream
// ---------------------------------------------------------------------------

func TestRoundTrip_Stream(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	original := streamDigest(t, buf)

	parsed, err := ParseSdbfFromString(original.String())
	mustNoError(t, err, "ParseSdbfFromString must succeed on a valid stream digest string")

	checkEqual(t, original.String(), parsed.String(), "round-tripped string must be identical")
	checkEqual(t, 100, parsed.Compare(original), "round-tripped digest must score 100 against original")
}

// ---------------------------------------------------------------------------
// 00070000  Round-trip DD
// ---------------------------------------------------------------------------

func TestRoundTrip_DD(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	original := ddDigest(t, buf, 1024)

	parsed, err := ParseSdbfFromString(original.String())
	mustNoError(t, err, "ParseSdbfFromString must succeed on a valid DD digest string")

	checkEqual(t, original.String(), parsed.String(), "round-tripped string must be identical")
	checkEqual(t, 100, parsed.Compare(original), "round-tripped digest must score 100 against original")
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
	checkNotPanics(t, func() { score = stream.Compare(dd) }, "cross-mode Compare must not panic")
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
	checkAtMost(t, sd1.Compare(sd2), 1, "dissimilar buffers must score 0 or 1")
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
	for i := 0; i < flips; i++ {
		idx := int(flipRng.Uint64() % uint64(size))
		buf2[idx] ^= 0xFF
	}

	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	checkGreater(t, sd1.Compare(sd2), 0, "lightly modified buffer must score > 0")
}

// ---------------------------------------------------------------------------
// 00110000  Concurrent compute
// ---------------------------------------------------------------------------

func TestConcurrent_ComputeMultiple(t *testing.T) {
	t.Parallel()
	const goroutines = 10
	results := make([]Sdbf, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			buf := randomBuf(1<<20, uint64(idx+10), uint64(idx+20))
			factory, err := CreateSdbfFromBytes(buf)
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

func TestConcurrent_Compare(t *testing.T) {
	t.Parallel()
	buf1 := randomBuf(1<<20, 1, 1)
	buf2 := randomBuf(1<<20, 1, 1) // same seed → same data → score 100
	sd1 := streamDigest(t, buf1)
	sd2 := streamDigest(t, buf2)
	expected := sd1.Compare(sd2)

	const goroutines = 20
	scores := make([]int, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scores[idx] = sd1.Compare(sd2)
		}(i)
	}
	wg.Wait()

	for i, score := range scores {
		checkEqual(t, expected, score,
			fmt.Sprintf("concurrent Compare result must be consistent (goroutine %d)", i))
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
// 00150000  entropy64IncInt clamp to zero
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

	result := entropy64IncInt(0, buf, ascii)
	checkEqual(t, uint64(0), result,
		"entropy calculation going negative must be clamped to 0")
}

// ---------------------------------------------------------------------------
// 00160000  entropy64IncInt clamp to entropyScale
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

	result := entropy64IncInt(uint64(entropyScale), buf, ascii)
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
	sd, err := ParseSdbfFromString(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	checkEqual(t, uint32(0), sd.FilterCount(), "FilterCount must be 0")
	checkEqual(t, -1, sd.Compare(sd),
		"Compare on a zero-filter digest must return -1")
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

	sd, err := ParseSdbfFromString(ddStr)
	mustNoError(t, err, "parsing a 2-filter DD digest with zero elem counts must succeed")

	checkEqual(t, uint32(2), sd.FilterCount(), "FilterCount must be 2")
	checkEqual(t, -1, sd.Compare(sd),
		"Compare with all-sparse filters and bfCount>1 must return -1 (denominator=0 path)")
}

// ---------------------------------------------------------------------------
// 00190000  generateChunkSdbf multi-chunk parallel
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

	sd.generateChunkSdbf(buf, chunkSize)
	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "multi-chunk digest must have at least one filter")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize after trim")
	checkLen(t, sd.hamming, int(sd.bfCount),
		"hamming slice length must equal bfCount")
	checkEqual(t, 100, sdbfScore(sd, sd), "multi-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00200000  generateChunkSdbf chunk size too small
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_ChunkSizeTooSmall verifies the guard that fires when
// chunkSize is not strictly greater than popWinSize.
func TestGenerateChunkSdbf_ChunkSizeTooSmall(t *testing.T) {
	t.Parallel()

	buf := randomBuf(MinFileSize, 8, 8)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(MinFileSize)

	checkPanics(t,
		func() { sd.generateChunkSdbf(buf, uint64(PopWinSize)) },
		"chunkSize <= popWinSize must panic",
	)
}

// ---------------------------------------------------------------------------
// 00210000  generateChunkSdbf exactly one chunk
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

	sd.generateChunkSdbf(buf, size)
	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "exactly-one-chunk digest must have at least one filter")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize")
	checkEqual(t, 100, sdbfScore(sd, sd),
		"exactly-one-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 00220000  generateChunkSdbf multi-chunk sparse last filter
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

	sd.generateChunkSdbf(buf, chunkSize)
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

// =========================================================================
// V. sdhash.go
// =========================================================================

// ---------------------------------------------------------------------------
// 00230000  ParseSdbfFromString error cases
// ---------------------------------------------------------------------------

func TestParseSdbf_ErrorCases(t *testing.T) {
	t.Parallel()

	validB64 := base64.StdEncoding.EncodeToString(make([]byte, 256))

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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSdbfFromString(tc.input)
			checkError(t, err, fmt.Sprintf("expected an error for case %q", tc.name))
		})
	}
}

// ---------------------------------------------------------------------------
// 00240000  ParseSdbfFromString stream without trailing newline
// ---------------------------------------------------------------------------

// TestParseSdbf_StreamWithoutTrailingNewline verifies that a digest string
// with the trailing '\n' stripped parses identically to the newline-terminated
// form.
func TestParseSdbf_StreamWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := streamDigest(t, buf)

	withoutNewline := strings.TrimRight(sd.String(), "\n")
	checkTrue(t, !strings.HasSuffix(withoutNewline, "\n"), "test string must not end with newline")

	parsed, err := ParseSdbfFromString(withoutNewline)
	mustNoError(t, err, "ParseSdbfFromString must succeed without trailing newline")
	checkEqual(t, sd.String(), parsed.String(),
		"digest parsed without trailing newline must be identical to original")
}

// ---------------------------------------------------------------------------
// 00250000  FeatureDensity zero-filled
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
// 00260000  FeatureDensity high entropy
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
// 00270000  FeatureDensity DD mode
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
// 00280000  FeatureDensity parsed digest
// ---------------------------------------------------------------------------

// TestFeatureDensity_ParsedDigest verifies that FeatureDensity is correct on
// a digest reconstructed from its wire format string.
func TestFeatureDensity_ParsedDigest(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 3, 3)
	original := streamDigest(t, buf)
	parsed, err := ParseSdbfFromString(original.String())
	mustNoError(t, err)
	checkEqual(t, original.FeatureDensity(), parsed.FeatureDensity(),
		"FeatureDensity must survive a round-trip through String/Parse")
}

// ---------------------------------------------------------------------------
// 00290000  FeatureDensity zero origFileSize
// ---------------------------------------------------------------------------

// TestFeatureDensity_ZeroOrigFileSize verifies that FeatureDensity returns 0
// when origFileSize is 0, exercising the early-return guard against division
// by zero.
func TestFeatureDensity_ZeroOrigFileSize(t *testing.T) {
	t.Parallel()

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	zeroSizeStream := "sdbf:03:1:-:0:sha1:256:5:7ff:160:1:42:" + b64 + "\n"

	sd, err := ParseSdbfFromString(zeroSizeStream)
	mustNoError(t, err, "parsing a stream digest with origFileSize=0 must succeed")
	checkEqual(t, float64(0), sd.FeatureDensity(),
		"FeatureDensity must return 0 when origFileSize is 0")
}
