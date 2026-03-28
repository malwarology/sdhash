package sdhash

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers — stdlib-only replacements for testify assert/require
// ---------------------------------------------------------------------------

// mustNoError stops the test immediately if err is non-nil (replaces require.NoError).
func mustNoError(t *testing.T, err error, msg ...string) {
	t.Helper()
	if err != nil {
		if len(msg) > 0 {
			t.Fatalf("%s: unexpected error: %v", msg[0], err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
}

// checkNoError records a failure if err is non-nil but lets the test continue (replaces assert.NoError).
func checkNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", msg, err)
	}
}

// checkError records a failure if err is nil (replaces assert.Error).
func checkError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected an error, got nil", msg)
	}
}

// checkEqual records a failure if got != want (replaces assert.Equal).
// For string values it shows the first point of divergence to aid debugging.
func checkEqual[T comparable](t *testing.T, want, got T, msg string) {
	t.Helper()
	if got != want {
		if ws, ok := any(want).(string); ok {
			gs := any(got).(string)
			t.Errorf("%s:\n  got:  %q\n  want: %q\n  first diff at byte %d",
				msg, gs, ws, firstDiff(ws, gs))
			return
		}
		t.Errorf("%s:\n  got:  %v\n  want: %v", msg, got, want)
	}
}

// firstDiff returns the index of the first byte at which a and b differ,
// or the length of the shorter string if one is a prefix of the other.
func firstDiff(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// checkNotNil records a failure if v is nil (replaces assert.NotNil).
func checkNotNil(t *testing.T, v any, msg string) {
	t.Helper()
	if v == nil {
		t.Errorf("%s: expected non-nil value, got nil", msg)
	}
}

// checkTrue records a failure if condition is false (replaces assert.True).
func checkTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Errorf("%s: condition was false", msg)
	}
}

// checkGreater records a failure if got <= threshold (replaces assert.Greater).
func checkGreater[T interface{ ~int | ~uint32 | ~uint64 | ~float64 }](t *testing.T, got, threshold T, msg string) {
	t.Helper()
	if got <= threshold {
		t.Errorf("%s: got %v, want > %v", msg, got, threshold)
	}
}

// checkAtLeast records a failure if got < min (replaces assert.GreaterOrEqual).
func checkAtLeast[T interface{ ~int | ~uint32 | ~uint64 | ~float64 }](t *testing.T, got, min T, msg string) {
	t.Helper()
	if got < min {
		t.Errorf("%s: got %v, want >= %v", msg, got, min)
	}
}

// checkAtMost records a failure if got > max (replaces assert.LessOrEqual).
func checkAtMost[T interface{ ~int | ~uint32 | ~uint64 | ~float64 }](t *testing.T, got, max T, msg string) {
	t.Helper()
	if got > max {
		t.Errorf("%s: got %v, want <= %v", msg, got, max)
	}
}

// checkLen records a failure if len(s) != want (replaces assert.Len).
func checkLen[T any](t *testing.T, s []T, want int, msg string) {
	t.Helper()
	if len(s) != want {
		t.Errorf("%s: got len %d, want %d", msg, len(s), want)
	}
}

// checkNotPanics records a failure if f() panics (replaces assert.NotPanics).
func checkNotPanics(t *testing.T, f func(), msg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: unexpected panic: %v", msg, r)
		}
	}()
	f()
}

// checkPanics records a failure if f() does NOT panic.
func checkPanics(t *testing.T, f func(), msg string) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected a panic, but none occurred", msg)
		}
	}()
	f()
}

// ---------------------------------------------------------------------------
// Shared test utilities
// ---------------------------------------------------------------------------

// randomBuf returns a deterministic pseudo-random buffer of the given size using
// a PCG source seeded with the provided seed values.
func randomBuf(size int, seed1, seed2 uint64) []byte {
	rng := rand.New(rand.NewPCG(seed1, seed2))
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(rng.Uint32())
	}
	return buf
}

// streamDigest computes a stream-mode digest for buf and stops the test on error.
func streamDigest(t *testing.T, buf []byte) Sdbf {
	t.Helper()
	factory, err := CreateSdbfFromBytes(buf)
	mustNoError(t, err)
	sd, err := factory.Compute()
	mustNoError(t, err)
	return sd
}

// ddDigest computes a DD-mode digest for buf with the given block size and stops the test on error.
func ddDigest(t *testing.T, buf []byte, blockSize uint32) Sdbf {
	t.Helper()
	factory, err := CreateSdbfFromBytes(buf)
	mustNoError(t, err)
	sd, err := factory.WithBlockSize(blockSize).Compute()
	mustNoError(t, err)
	return sd
}

// ---------------------------------------------------------------------------
// 1. Error cases for CreateSdbfFromBytes
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
// 2. Stream mode digest generation
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

func TestStreamMode_SelfComparison(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := streamDigest(t, buf)
	checkEqual(t, 100, sd.Compare(sd), "self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 3. DD (block-aligned) mode digest generation
// ---------------------------------------------------------------------------

func TestDDMode_BasicProperties(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := ddDigest(t, buf, 1024)

	checkNotNil(t, sd, "DD digest must not be nil")
	checkTrue(t, strings.HasPrefix(sd.String(), "sdbf-dd:03:1:-:"), "String should start with DD prefix")
}

func TestDDMode_SelfComparison(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := ddDigest(t, buf, 1024)
	checkEqual(t, 100, sd.Compare(sd), "DD self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 4. Round-trip: String() → ParseSdbfFromString() → String()
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
// 5. Cross-mode comparison
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
// 6. Dissimilar data scores low
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
// 7. Similar data scores high
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
// 9. Concurrent safety
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

// ---------------------------------------------------------------------------
// 10. Issue 1 regression — default index bug
// ---------------------------------------------------------------------------

func TestIssue1DefaultIndexNotCreated(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/issue1.bin")
	mustNoError(t, err)

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	sd, err := factory.Compute()
	mustNoError(t, err)

	// Cast to internal type to verify bloom filter counts directly.
	// These values were confirmed against the C++ reference implementation.
	internal := sd.(*sdbf)
	checkEqual(t, uint32(66), internal.bfCount,
		"bfCount should match C++ reference (regression: issue #1)")
	checkEqual(t, uint32(64), internal.lastCount,
		"lastCount should match C++ reference (regression: issue #1)")

	checkEqual(t, 100, sd.Compare(sd), "self-comparison must return 100")
}

// ---------------------------------------------------------------------------
// 11. Issue 1 stream hash — exact wire-format match against reference output
// ---------------------------------------------------------------------------

func TestIssue1StreamHash_MatchesReference(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/issue1.bin")
	mustNoError(t, err)

	expectedBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	expected := string(expectedBytes)
	// Normalize: ensure exactly one trailing newline regardless of how the
	// reference file was saved.
	expected = strings.TrimRight(expected, "\r\n") + "\n"

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	sd, err := factory.Compute()
	mustNoError(t, err)

	checkEqual(t, expected, sd.String(),
		"stream digest wire format must match the C++ reference output in testdata/issue1.stream")
}

// ---------------------------------------------------------------------------
// 12. Issue 1 DD hash — exact wire-format match against reference output
// ---------------------------------------------------------------------------

func TestIssue1DDHash_MatchesReference(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/issue1.bin")
	mustNoError(t, err)

	expectedBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)
	expected := string(expectedBytes)
	expected = strings.TrimRight(expected, "\r\n") + "\n"

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	// The DD reference was produced with a 1 MiB (1048576-byte) block size,
	// as shown by the ddBlockSize field in testdata/issue1.dd.
	const ddBlockSize = 1048576
	sd, err := factory.WithBlockSize(ddBlockSize).Compute()
	mustNoError(t, err)

	checkEqual(t, expected, sd.String(),
		"DD digest wire format must match the C++ reference output in testdata/issue1.dd")
}

// ---------------------------------------------------------------------------
// 13. Issue 1 — cross-check stream and DD digests against each other
// ---------------------------------------------------------------------------

func TestIssue1_StreamAndDDParsedScoreInRange(t *testing.T) {
	t.Parallel()

	streamBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	ddBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)

	streamSD, err := ParseSdbfFromString(string(streamBytes))
	mustNoError(t, err, "ParseSdbfFromString must succeed on issue1.stream")

	ddSD, err := ParseSdbfFromString(string(ddBytes))
	mustNoError(t, err, "ParseSdbfFromString must succeed on issue1.dd")

	// Both digests were produced from the same file, so a cross-mode comparison
	// must not panic and must return a value in [0, 100].
	var score int
	checkNotPanics(t, func() { score = streamSD.Compare(ddSD) }, "cross-mode Compare must not panic")
	checkAtLeast(t, score, 0, "cross-mode score must be >= 0")
	checkAtMost(t, score, 100, "cross-mode score must be <= 100")
}

// ---------------------------------------------------------------------------
// 14. ParseSdbfFromString round-trips for both reference files
// ---------------------------------------------------------------------------

func TestIssue1_RoundTrip_StreamReference(t *testing.T) {
	t.Parallel()
	rawBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	raw := strings.TrimRight(string(rawBytes), "\r\n") + "\n"

	sd, err := ParseSdbfFromString(raw)
	mustNoError(t, err)

	checkEqual(t, raw, sd.String(), "ParseSdbfFromString→String must be identity for issue1.stream")
	checkEqual(t, 100, sd.Compare(sd), "self-comparison of parsed issue1.stream digest must be 100")
}

func TestIssue1_RoundTrip_DDReference(t *testing.T) {
	t.Parallel()
	rawBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)
	raw := strings.TrimRight(string(rawBytes), "\r\n") + "\n"

	sd, err := ParseSdbfFromString(raw)
	mustNoError(t, err)

	checkEqual(t, raw, sd.String(), "ParseSdbfFromString→String must be identity for issue1.dd")
	checkEqual(t, 100, sd.Compare(sd), "self-comparison of parsed issue1.dd digest must be 100")
}

// ---------------------------------------------------------------------------
// 14b. ParseSdbfFromString — stream digest without trailing newline
// ---------------------------------------------------------------------------

// TestParseSdbf_StreamWithoutTrailingNewline exercises the refactored newline
// stripping in ParseSdbfFromString, which now checks the last byte directly
// rather than using the error return as a proxy. A digest string with the
// trailing '\n' stripped is a legitimate input (e.g. after string trimming)
// and must parse identically to the newline-terminated form.
func TestParseSdbf_StreamWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	buf := randomBuf(1<<20, 1, 1)
	sd := streamDigest(t, buf)

	// Strip the trailing newline that String() always appends.
	withoutNewline := strings.TrimRight(sd.String(), "\n")
	checkTrue(t, !strings.HasSuffix(withoutNewline, "\n"), "test string must not end with newline")

	parsed, err := ParseSdbfFromString(withoutNewline)
	mustNoError(t, err, "ParseSdbfFromString must succeed without trailing newline")
	checkEqual(t, sd.String(), parsed.String(),
		"digest parsed without trailing newline must be identical to original")
}

// ---------------------------------------------------------------------------
// 15. generateChunkSdbf — multi-chunk parallel path
// ---------------------------------------------------------------------------

// newTestSdbf builds a minimal internal sdbf ready for generateChunkSdbf.
func newTestSdbf(t *testing.T) *sdbf {
	t.Helper()
	sd := &sdbf{
		bfSize:         BfSize,
		bfCount:        1,
		bigFilters:     make([]*bloomFilter, 0, 1),
		popWinSize:     PopWinSize,
		threshold:      Threshold,
		blockSize:      BlockSize,
		entropyWinSize: EntropyWinSize,
		maxElem:        MaxElem,
	}
	bf, err := newBloomFilter(bigFilter, defaultHashCount, bigFilterElem)
	mustNoError(t, err)
	sd.bigFilters = append(sd.bigFilters, bf)
	return sd
}

// TestGenerateChunkSdbf_MultiChunk exercises the parallel goroutine phase by
// calling generateChunkSdbf directly (white-box) with a 1 MiB chunk size and a
// 3.5 MiB buffer. That gives qt=3, rem=0.5 MiB, totalChunks=4, which is enough
// to drive the semaphore pool and both the loop goroutines and the rem goroutine.
func TestGenerateChunkSdbf_MultiChunk(t *testing.T) {
	t.Parallel()

	const chunkSize = 1 << 20
	const totalSize = 3*chunkSize + chunkSize/2 // 3.5 MiB → qt=3, rem=0.5MiB

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

	checkEqual(t, 100, sdbfScore(sd, sd, 0), "multi-chunk digest must self-compare at 100")
}

// TestGenerateChunkSdbf_ChunkSizeTooSmall verifies the guard that fires when
// chunkSize is not strictly greater than popWinSize. The refactor converted
// this from an error return to a panic, since the condition represents a
// programming error (the call site uses a compile-time constant that always
// satisfies the constraint).
func TestGenerateChunkSdbf_ChunkSizeTooSmall(t *testing.T) {
	t.Parallel()

	buf := randomBuf(MinFileSize, 8, 8)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(MinFileSize)

	checkPanics(t,
		func() { sd.generateChunkSdbf(buf, uint64(PopWinSize)) }, // chunkSize == popWinSize → panic
		"chunkSize <= popWinSize must panic",
	)
}

// ---------------------------------------------------------------------------
// 16. ParseSdbfFromString — error paths
// ---------------------------------------------------------------------------

func TestParseSdbf_ErrorCases(t *testing.T) {
	t.Parallel()

	// Base64 of 256 zero bytes — used to build syntactically plausible strings.
	validB64 := base64.StdEncoding.EncodeToString(make([]byte, 256))

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "truncated after magic colon",
			input: "sdbf:",
		},
		{
			name:  "unsupported version",
			input: "sdbf:99:1:-:1048576:sha1:256:5:7ff:160:1:100:" + validB64 + "\n",
		},
		{
			name:  "unrecognized magic",
			input: "badmagic:03:1:-:1048576:sha1:256:5:7ff:160:1:100:" + validB64 + "\n",
		},
		{
			name:  "non-numeric file size",
			input: "sdbf:03:1:-:notanumber:sha1:256:5:7ff:160:1:100:" + validB64 + "\n",
		},
		{
			name:  "non-numeric bfSize",
			input: "sdbf:03:1:-:1048576:sha1:notanumber:5:7ff:160:1:100:" + validB64 + "\n",
		},
		{
			name:  "invalid base64 in stream buffer",
			input: "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:100:!!invalid!!\n",
		},
		{
			name:  "truncated DD missing block size field",
			input: "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:",
		},
		{
			name:  "DD invalid hex elem count",
			input: "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:zz:" + validB64 + "\n",
		},
		{
			name:  "DD invalid base64 block data",
			input: "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:!!invalid!!\n",
		},
		// --- Truncation tests: each one advances one field further than the previous,
		// covering the error-return body of every skipField / readUint64Field call
		// inside ParseSdbfFromString that no earlier test reaches. ---
		{
			// Truncated after version — skipField for namelen hits EOF.
			name:  "truncated after version",
			input: "sdbf:03:",
		},
		{
			// Truncated after namelen — skipField for name hits EOF.
			name:  "truncated after namelen",
			input: "sdbf:03:1:",
		},
		{
			// Truncated after origFileSize — skipField for hash algorithm hits EOF.
			name:  "truncated after origFileSize",
			input: "sdbf:03:1:-:1048576:",
		},
		{
			// Truncated after bfSize — skipField for hashCount hits EOF.
			name:  "truncated after bfSize",
			input: "sdbf:03:1:-:1048576:sha1:256:",
		},
		{
			// Truncated after hashCount — skipField for bitMask hits EOF.
			name:  "truncated after hashCount",
			input: "sdbf:03:1:-:1048576:sha1:256:5:",
		},
		{
			// Truncated after bitMask — readUint64Field for maxElem hits EOF.
			name:  "truncated after bitMask",
			input: "sdbf:03:1:-:1048576:sha1:256:5:7ff:",
		},
		{
			// Truncated after maxElem — readUint64Field for bfCount hits EOF.
			name:  "truncated after maxElem",
			input: "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:",
		},
		{
			// Truncated after bfCount in stream mode — readUint64Field for lastCount hits EOF.
			name:  "stream truncated after bfCount",
			input: "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:",
		},
		{
			// DD with bfCount=2, filter 0 complete, then truncated.
			// readField for filter 1's elem count hits EOF.
			name: "DD readField fails on second filter",
			input: "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" +
				validB64 + ":",
		},
		{
			// DD with bfCount=2, filter 0 complete, filter 1 elem count valid,
			// filter 1 base64 data is invalid — base64 decode fails for filter 1.
			name: "DD base64 decode fails on second filter",
			input: "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" +
				validB64 + ":c0:!!bad!!",
		},
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
// 17. CompareSample with a non-zero sample value
// ---------------------------------------------------------------------------

// TestCompareSample_NonZeroSample exercises the branch in sdbfScore where
// sample > 0 and bfCount > sample, so only the first `sample` filters are used.
func TestCompareSample_NonZeroSample(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 6, 6)
	sd := streamDigest(t, buf)

	if sd.FilterCount() < 2 {
		t.Skip("need FilterCount >= 2 to exercise the sample code path")
	}

	sample := sd.FilterCount() / 2
	score := sd.CompareSample(sd, sample)
	checkAtLeast(t, score, 0, "sampled score must be >= 0")
	checkAtMost(t, score, 100, "sampled score must be <= 100")

	// sample=0 must produce the same result as Compare (which passes 0 internally).
	checkEqual(t, sd.Compare(sd), sd.CompareSample(sd, 0),
		"CompareSample with sample=0 must equal Compare")
}

// ---------------------------------------------------------------------------
// 18. newBloomFilter — invalid size error branch
// ---------------------------------------------------------------------------

func TestNewBloomFilter_InvalidSize(t *testing.T) {
	t.Parallel()

	// Size less than the minimum of 64.
	_, err := newBloomFilter(32, defaultHashCount, 100)
	checkError(t, err, "size 32 (< 64) must return an error")

	// Size of zero.
	_, err = newBloomFilter(0, defaultHashCount, 100)
	checkError(t, err, "size 0 must return an error")

	// Size that is not a power of two.
	_, err = newBloomFilter(100, defaultHashCount, 100)
	checkError(t, err, "size 100 (not a power of 2) must return an error")

	// Exact minimum valid size must succeed.
	bf, err := newBloomFilter(64, defaultHashCount, 100)
	checkNoError(t, err, "size 64 must succeed")
	if bf == nil {
		t.Errorf("size 64: expected non-nil bloom filter, got nil")
	} else {
		checkLen(t, bf.buffer, 64, "size 64: bloom filter buffer length")
	}
}

// ---------------------------------------------------------------------------
// 19. bloomFilter.fold — bfSize == 32 early-exit branch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 20. entropy64IncInt — clamping branches
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
	ascii['A'] = 1  // 'A' appears once in the window
	ascii['B'] = 50 // 'B' appears 50 times in the window

	// buf[0] leaves the window; buf[64] enters the window.
	buf := make([]uint8, 65)
	buf[0] = 'A'  // oldCharCnt=1  → oldDiff is large positive
	buf[64] = 'B' // newCharCnt=50 → newDiff is negative (past the entropy peak)

	result := entropy64IncInt(0, buf, ascii)
	checkEqual(t, uint64(0), result,
		"entropy calculation going negative must be clamped to 0")
}

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
	ascii['A'] = 50 // 'A' appears 50 times in the window
	ascii['B'] = 1  // 'B' appears once in the window

	buf := make([]uint8, 65)
	buf[0] = 'A'  // oldCharCnt=50 → oldDiff negative (past entropy peak)
	buf[64] = 'B' // newCharCnt=1  → newDiff large positive

	result := entropy64IncInt(uint64(entropyScale), buf, ascii)
	checkEqual(t, uint64(entropyScale), result,
		"entropy calculation exceeding entropyScale must be clamped to entropyScale")
}

// ---------------------------------------------------------------------------
// 21. sdbfScore edge cases — zero bfCount and zero denominator
// ---------------------------------------------------------------------------

// TestSdbfScore_ZeroBfCount verifies that comparing a digest that has no bloom
// filters returns -1. This exercises the bfCount1==0 guard in sdbfScore.
// A stream digest string with bfCount=0 is valid to parse (the base64 data
// section is empty) but has nothing to compare.
func TestSdbfScore_ZeroBfCount(t *testing.T) {
	t.Parallel()

	// The String() method for a zero-filter stream digest writes no base64 data,
	// producing the format: "...:<maxElem>:0:<lastCount>:\n".
	emptyStream := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:0:0:\n"
	sd, err := ParseSdbfFromString(emptyStream)
	mustNoError(t, err, "parsing a bfCount=0 stream digest must succeed")

	checkEqual(t, uint32(0), sd.FilterCount(), "FilterCount must be 0")
	// With no filters, sdbfScore returns the sentinel -1.
	checkEqual(t, -1, sd.Compare(sd),
		"Compare on a zero-filter digest must return -1")
}

// TestSdbfScore_DenominatorZero verifies the denominator==0 guard in sdbfScore.
// The guard fires when bfCount1 > 1 and every filter has an element count below
// minElemCount (16), so sparseCount == bfCount1 and denominator = 0.
// A DD digest with two filters both having elemCount=0 (hex "00") triggers this.
func TestSdbfScore_DenominatorZero(t *testing.T) {
	t.Parallel()

	b64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	// Two filters, each with elemCount=0 ("00" in hex). Both filters are sparse
	// (0 < minElemCount=16), so sparseCount=2=bfCount and denominator=0.
	ddStr := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:00:" +
		b64 + ":00:" + b64 + "\n"

	sd, err := ParseSdbfFromString(ddStr)
	mustNoError(t, err, "parsing a 2-filter DD digest with zero elem counts must succeed")

	checkEqual(t, uint32(2), sd.FilterCount(), "FilterCount must be 2")
	// denominator = bfCount - sparseCount = 2 - 2 = 0 → scoreSum-- → return -1.
	checkEqual(t, -1, sd.Compare(sd),
		"Compare with all-sparse filters and bfCount>1 must return -1 (denominator=0 path)")
}

// ---------------------------------------------------------------------------
// 22. mustNewBloomFilter — panic branch
// ---------------------------------------------------------------------------

// TestMustNewBloomFilter_PanicsOnInvalidSize verifies that mustNewBloomFilter
// panics when given a size that newBloomFilter rejects. In production code,
// mustNewBloomFilter is only ever called with the compile-time constant
// bigFilter=16384, so this panic is unreachable at runtime — but the branch
// must be tested to confirm the panic contract is correctly implemented.
func TestMustNewBloomFilter_PanicsOnInvalidSize(t *testing.T) {
	t.Parallel()
	checkPanics(t,
		func() { mustNewBloomFilter(100, defaultHashCount, 100) }, // 100 is not a power of two
		"mustNewBloomFilter with an invalid size must panic",
	)
}

// ---------------------------------------------------------------------------
// 23. generateChunkSdbf — single-chunk path, qt == 1 branch
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_ExactlyOneChunk exercises the qt==1 branch inside the
// single-chunk fast path. It fires when fileSize == chunkSize exactly
// (qt=1, rem=0, totalChunks=1). All other tests pass a 1 MiB buffer against
// the 32 MiB default chunkSize, giving qt=0 every time and leaving this
// branch uncovered.
func TestGenerateChunkSdbf_ExactlyOneChunk(t *testing.T) {
	t.Parallel()

	const size = 1 << 19 // 512 KiB
	buf := randomBuf(size, 42, 42)
	sd := newTestSdbf(t)
	sd.origFileSize = uint64(size)

	// chunkSize == fileSize → qt=1, rem=0, totalChunks=1, qt==1 branch taken.
	sd.generateChunkSdbf(buf, size)

	sd.computeHamming()

	checkGreater(t, sd.bfCount, uint32(0), "exactly-one-chunk digest must have at least one filter")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize")
	checkEqual(t, 100, sdbfScore(sd, sd, 0),
		"exactly-one-chunk digest must self-compare at 100")
}

// ---------------------------------------------------------------------------
// 24. generateChunkSdbf — multi-chunk path, sparse last filter pruning
// ---------------------------------------------------------------------------

// TestGenerateChunkSdbf_MultiChunk_SparseLastFilter exercises the
// "drop last sparse filter" condition in the multi-chunk path
// (core.go: if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8).
//
// Construction: chunkSize = 10 KiB, fileSize = 20 KiB (qt=2, rem=0 →
// multi-chunk path). With seed=1 and 10 KiB of random data, the first
// chunk produces exactly enough unique features to fill one complete filter
// (bfCount → 2, lastCount → 0). The all-zeros second chunk adds 0 features.
// The pruning condition (bfCount=2 > 1, lastCount=0 < maxElem/8=20) fires,
// decrementing bfCount back to 1 and setting lastCount = maxElem. The final
// state (bfCount=1, lastCount=160) is the observable proof that the pruning
// branch executed. These values were confirmed empirically via a parameter scan.
func TestGenerateChunkSdbf_MultiChunk_SparseLastFilter(t *testing.T) {
	t.Parallel()

	const chunkSize = 10240 // 10 KiB — calibrated so the first chunk fills exactly one filter
	buf := make([]byte, 2*chunkSize)
	copy(buf[:chunkSize], randomBuf(chunkSize, 1, 1))
	// Second chunk: all-zeros → adds 0 unique features → lastCount stays 0.

	sd := newTestSdbf(t)
	sd.origFileSize = uint64(len(buf))

	// qt=2, rem=0 → totalChunks=2 → multi-chunk path.
	sd.generateChunkSdbf(buf, chunkSize)
	sd.computeHamming()

	// After pruning: bfCount was decremented from 2→1 and lastCount set to maxElem.
	// This is the observable signature that lines 262-265 executed.
	checkEqual(t, uint32(1), sd.bfCount,
		"bfCount must be 1 after sparse-filter pruning decrements it from 2")
	checkEqual(t, sd.maxElem, sd.lastCount,
		"lastCount must equal maxElem after pruning resets it")
	checkEqual(t, int(sd.bfCount)*int(sd.bfSize), len(sd.buffer),
		"buffer length must equal bfCount*bfSize after pruning and trim")
	checkEqual(t, 100, sdbfScore(sd, sd, 0),
		"pruned multi-chunk digest must self-compare at 100")
}
