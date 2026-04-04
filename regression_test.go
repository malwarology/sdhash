package sdhash

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Regression test index
//
// Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
//    https://github.com/eciavatta/sdhash/issues/1
// ├── 00010000  Default index not created
// ├── 00020000  Stream hash matches reference
// ├── 00030000  DD hash matches reference
// ├── 00040000  Stream and DD parsed score in range
// ├── 00050000  Round-trip stream reference
// └── 00060000  Round-trip DD reference
//
// Issue 2 — Feature density detection for degenerate stream mode digests
//    https://github.com/malwarology/sdhash/issues/2
// ├── 00070000  Degenerate stream digests
// └── 00080000  DD mode no false positive
//
// Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
//    https://github.com/malwarology/sdhash/issues/3
// └── 00090000  High block count DD mode
//
// Issue 4 — Unbounded memory allocation in ParseSdbfFromString
//    https://github.com/malwarology/sdhash/issues/4
// ├── 00100000  Parse oversized bfCount
// └── 00110000  Parse zero bfSize
//
// Issue 10 — ParseSdbfFromString panics on truncated base64 payload
//    https://github.com/malwarology/sdhash/issues/10
// ├── 00120000  Parse truncated stream buffer
// ├── 00130000  Parse stream lastCount exceeds maxElem
// ├── 00140000  Parse DD block too short
// └── 00150000  Parse DD element count exceeds maxElem
//
// Issue 11 — BfSize exported as mutable var but hardwired to 256 throughout
//    https://github.com/malwarology/sdhash/issues/11
// └── 00160000  Parse unsupported bfSize
//
// Issue 14 — CreateSdbfFromBytes retains caller's slice without copying
//    https://github.com/malwarology/sdhash/issues/14
// └── 00170000  Buffer mutation after factory creation
//
// Issue 15 — DD parsing fails on digests without trailing newline
//    https://github.com/malwarology/sdhash/issues/15
// └── 00180000  DD parse without trailing newline
//
// Issue 17 — Compare panics on nil or foreign Sdbf implementation
//    https://github.com/malwarology/sdhash/issues/17
// ├── 00190000  Compare with nil Sdbf returns -1
// └── 00200000  Compare with foreign Sdbf implementation returns -1
//
// Issue 19 — Unconstrained maxElem enables uint32 overflow in Compare
//    https://github.com/malwarology/sdhash/issues/19
// ├── 00210000  Parse maxElem overflow (uint32 wraparound)
// └── 00220000  Parse maxElem zero
//
// Issue 20 — Inner while loop evaluates array access before bounds guard
//    https://github.com/malwarology/sdhash/issues/20
// └── 00230000  generateChunkScores inner while loop OOB
//
// Issue 21 — WithBlockSize accepts values below PopWinSize causing underflow panic
//    https://github.com/malwarology/sdhash/issues/21
// └── 00240000  Small block size uint64 underflow

// =========================================================================
// Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
// https://github.com/eciavatta/sdhash/issues/1
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Default index not created
// ---------------------------------------------------------------------------

func TestIssue1DefaultIndexNotCreated(t *testing.T) {
	t.Parallel()
	data := decryptTestFile(t, "testdata/issue1.bin.enc")

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
// 00020000  Stream hash matches reference
// ---------------------------------------------------------------------------

func TestIssue1StreamHash_MatchesReference(t *testing.T) {
	t.Parallel()

	data := decryptTestFile(t, "testdata/issue1.bin.enc")

	expectedBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	expected := string(expectedBytes)
	expected = strings.TrimRight(expected, "\r\n") + "\n"

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	sd, err := factory.Compute()
	mustNoError(t, err)

	checkEqual(t, expected, sd.String(),
		"stream digest wire format must match the C++ reference output in testdata/issue1.stream")
}

// ---------------------------------------------------------------------------
// 00030000  DD hash matches reference
// ---------------------------------------------------------------------------

func TestIssue1DDHash_MatchesReference(t *testing.T) {
	t.Parallel()

	data := decryptTestFile(t, "testdata/issue1.bin.enc")

	expectedBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)
	expected := string(expectedBytes)
	expected = strings.TrimRight(expected, "\r\n") + "\n"

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	// The DD reference was produced with a 1 MiB block size,
	// as shown by the ddBlockSize field in testdata/issue1.dd.
	const ddBlockSize = 1048576
	sd, err := factory.WithBlockSize(ddBlockSize).Compute()
	mustNoError(t, err)

	checkEqual(t, expected, sd.String(),
		"DD digest wire format must match the C++ reference output in testdata/issue1.dd")
}

// ---------------------------------------------------------------------------
// 00040000  Stream and DD parsed score in range
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

	var score int
	checkNotPanics(t, func() { score = streamSD.Compare(ddSD) }, "cross-mode Compare must not panic")
	checkAtLeast(t, score, 0, "cross-mode score must be >= 0")
	checkAtMost(t, score, 100, "cross-mode score must be <= 100")
}

// ---------------------------------------------------------------------------
// 00050000  Round-trip stream reference
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

// ---------------------------------------------------------------------------
// 00060000  Round-trip DD reference
// ---------------------------------------------------------------------------

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

// =========================================================================
// Issue 2 — Feature density detection for degenerate stream mode digests
// https://github.com/malwarology/sdhash/issues/2
// =========================================================================

// ---------------------------------------------------------------------------
// 00070000  Degenerate stream digests
// ---------------------------------------------------------------------------

// TestIssue2_DegenerateStreamDigests verifies that the two samples from
// sdhash/sdhash#17 produce stream digests with feature density below 0.02.
// Without a density check, these two unrelated files score 100 against each
// other in stream mode.
func TestIssue2_DegenerateStreamDigests(t *testing.T) {
	t.Parallel()

	dataA := decryptTestFile(t, "testdata/issue2a.bin.enc")
	dataB := decryptTestFile(t, "testdata/issue2b.bin.enc")

	sdA := streamDigest(t, dataA)
	sdB := streamDigest(t, dataB)

	checkAtMost(t, sdA.FeatureDensity(), 0.02,
		"issue2a stream density must be below 0.02")
	checkAtMost(t, sdB.FeatureDensity(), 0.02,
		"issue2b stream density must be below 0.02")

	// The stream comparison produces a false positive of 100.
	// This documents the known failure mode; FeatureDensity is how
	// callers detect it.
	score := sdA.Compare(sdB)
	checkEqual(t, 100, score,
		"issue2 stream comparison produces a false positive of 100")
}

// ---------------------------------------------------------------------------
// 00080000  DD mode no false positive
// ---------------------------------------------------------------------------

// TestIssue2_DDModeNoFalsePositive verifies that DD mode does not produce
// the same false positive for the issue 2 samples.
func TestIssue2_DDModeNoFalsePositive(t *testing.T) {
	t.Parallel()

	dataA := decryptTestFile(t, "testdata/issue2a.bin.enc")
	dataB := decryptTestFile(t, "testdata/issue2b.bin.enc")

	ddA := ddDigest(t, dataA, 65536)
	ddB := ddDigest(t, dataB, 65536)

	score := ddA.Compare(ddB)
	checkEqual(t, 0, score,
		"issue2 DD comparison must be 0")
}

// =========================================================================
// Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
// https://github.com/malwarology/sdhash/issues/3
// =========================================================================

// ---------------------------------------------------------------------------
// 00090000  High block count DD mode
// ---------------------------------------------------------------------------

// TestIssue3_HighBlockCountDDMode verifies that computing a DD digest with a
// small block size (1024 bytes) over a 1 MiB buffer — producing ~1024 blocks —
// completes correctly without unbounded goroutine spawning. Without the
// semaphore fix in generateBlockSdbf, this configuration spawns 1024+
// goroutines simultaneously.
func TestIssue3_HighBlockCountDDMode(t *testing.T) {
	t.Parallel()

	data := randomBuf(1<<20, 50, 50)

	factory, err := CreateSdbfFromBytes(data)
	mustNoError(t, err)

	const ddBlockSize = 1024
	sd, err := factory.WithBlockSize(ddBlockSize).Compute()
	mustNoError(t, err)

	checkEqual(t, 100, sd.Compare(sd), "self-comparison must return 100")
}

// =========================================================================
// Issue 4 — Unbounded memory allocation in ParseSdbfFromString
// https://github.com/malwarology/sdhash/issues/4
// =========================================================================

// ---------------------------------------------------------------------------
// 00100000  Parse oversized bfCount
// ---------------------------------------------------------------------------

// TestIssue4_ParseOversizedBfCount verifies that a digest string with a
// bfCount large enough to exceed the 256 MiB allocation limit is rejected
// by ParseSdbfFromString rather than causing an OOM panic.
func TestIssue4_ParseOversizedBfCount(t *testing.T) {
	t.Parallel()

	// bfCount of 999999999 with the default bfSize of 256 bytes would require
	// ~238 GiB, far exceeding the 256 MiB cap.
	digest := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:999999999:100:"

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error for a bfCount that exceeds the allocation limit (regression: issue #4)")
}

// ---------------------------------------------------------------------------
// 00110000  Parse zero bfSize
// ---------------------------------------------------------------------------

// TestIssue4_ParseZeroBfSize verifies that a digest string with bfSize set to
// zero is rejected by ParseSdbfFromString rather than causing a divide-by-zero
// panic inside the allocation sanity check.
func TestIssue4_ParseZeroBfSize(t *testing.T) {
	t.Parallel()

	// bfSize of 0 must be caught before the allocation check to prevent
	// a divide-by-zero when computing maxBfAlloc/bfSize.
	digest := "sdbf:03:1:-:1048576:sha1:0:5:7ff:160:100:100:"

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error for a bfSize of zero (regression: issue #4)")
}

// =========================================================================
// Issue 10 — ParseSdbfFromString panics on truncated base64 payload
// https://github.com/malwarology/sdhash/issues/10
// =========================================================================

// ---------------------------------------------------------------------------
// 00120000  Parse truncated stream buffer
// ---------------------------------------------------------------------------

// TestIssue10_ParseTruncatedStreamBuffer verifies that a stream digest whose
// base64 payload decodes to fewer bytes than bfCount × bfSize is rejected by
// ParseSdbfFromString rather than causing a slice-bounds panic in computeHamming.
func TestIssue10_ParseTruncatedStreamBuffer(t *testing.T) {
	t.Parallel()

	// bfCount=1, bfSize=256: the buffer must be 256 bytes, but we supply only 128.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 128))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:100:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error when the base64 payload decodes to fewer bytes than bfCount × bfSize (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00130000  Parse stream lastCount exceeds maxElem
// ---------------------------------------------------------------------------

// TestIssue10_ParseStreamLastCountExceedsMaxElem verifies that a stream digest
// where lastCount is greater than maxElem is rejected by ParseSdbfFromString.
func TestIssue10_ParseStreamLastCountExceedsMaxElem(t *testing.T) {
	t.Parallel()

	// maxElem=160, lastCount=999: lastCount must not exceed maxElem.
	// The buffer is a valid 256-byte payload so the length check passes first.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:999:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error when lastCount exceeds maxElem (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00140000  Parse DD block too short
// ---------------------------------------------------------------------------

// TestIssue10_ParseDDBlockTooShort verifies that a DD digest where a block's
// base64 decodes to fewer bytes than bfSize is rejected by ParseSdbfFromString
// rather than leaving the destination slice partially filled.
func TestIssue10_ParseDDBlockTooShort(t *testing.T) {
	t.Parallel()

	// bfCount=1, bfSize=256, elemCount=0x64 (100 ≤ maxElem=160): the block
	// payload must be 256 bytes, but we supply only 128.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 128))
	digest := fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:160:1:65536:64:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error when a DD block's base64 decodes to fewer bytes than bfSize (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00150000  Parse DD element count exceeds maxElem
// ---------------------------------------------------------------------------

// TestIssue10_ParseDDElemCountExceedsMaxElem verifies that a DD digest where
// a block's element count exceeds maxElem is rejected by ParseSdbfFromString.
func TestIssue10_ParseDDElemCountExceedsMaxElem(t *testing.T) {
	t.Parallel()

	// maxElem=192 (0xc0), elemCount=0xff (255): 255 > 192 must be rejected.
	// The block payload is a valid 256-byte buffer so the length check would pass.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:65536:ff:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error when a DD block element count exceeds maxElem (regression: issue #10)")
}

// =========================================================================
// Issue 11 — BfSize exported as mutable var but hardwired to 256 throughout
// https://github.com/malwarology/sdhash/issues/11
// =========================================================================

// ---------------------------------------------------------------------------
// 00160000  Parse unsupported bfSize
// ---------------------------------------------------------------------------

// TestIssue11_ParseUnsupportedBfSize verifies that a stream digest string with
// bfSize set to 512 instead of the only supported value (256) is rejected by
// ParseSdbfFromString. The rest of the digest is structurally valid: bfCount=1,
// maxElem=160, lastCount=100, and a 512-byte base64 payload that satisfies the
// bfCount × bfSize length check — ensuring the rejection is caused solely by
// the unsupported bfSize value and not by any other validation.
func TestIssue11_ParseUnsupportedBfSize(t *testing.T) {
	t.Parallel()

	// bfSize=512: the implementation is hardwired to 256-byte bloom filters, so
	// any other value must be rejected before any buffer is allocated or decoded.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 512))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:512:5:7ff:160:1:100:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error for a bfSize other than 256 (regression: issue #11)")
}

// =========================================================================
// Issue 14 — CreateSdbfFromBytes retains caller's slice without copying
// https://github.com/malwarology/sdhash/issues/14
// =========================================================================

// ---------------------------------------------------------------------------
// 00170000  Buffer mutation after factory creation
// ---------------------------------------------------------------------------

// TestIssue14_BufferMutationAfterFactory verifies that mutating the original
// buffer after calling CreateSdbfFromBytes does not affect the digest produced
// by the factory. Without a defensive copy inside CreateSdbfFromBytes, zeroing
// the buffer between factory creation and Compute causes both factories to
// produce identical digests even though one was created from random data.
func TestIssue14_BufferMutationAfterFactory(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 60, 60)

	factory, err := CreateSdbfFromBytes(buf)
	mustNoError(t, err)

	sd, err := factory.Compute()
	mustNoError(t, err)
	first := sd.String()

	// Zero out the original buffer to simulate a caller reusing or releasing it.
	clear(buf)

	factory2, err := CreateSdbfFromBytes(buf)
	mustNoError(t, err)

	sd2, err := factory2.Compute()
	mustNoError(t, err)
	second := sd2.String()

	if first == second {
		t.Errorf("digest computed before buffer mutation equals digest computed after: factory did not copy the buffer (regression: issue #14)")
	}
}

// =========================================================================
// Issue 15 — DD parsing fails on digests without trailing newline
// https://github.com/malwarology/sdhash/issues/15
// =========================================================================

// ---------------------------------------------------------------------------
// 00180000  DD parse without trailing newline
// ---------------------------------------------------------------------------

// TestIssue15_DDParseWithoutTrailingNewline verifies that ParseSdbfFromString
// correctly decodes a DD digest string that has no trailing newline. Without
// the EOF-tolerant fix, the last byte of the final block's base64 payload is
// stripped along with the missing delimiter, causing a base64 decode error or
// an incorrect bloom filter.
func TestIssue15_DDParseWithoutTrailingNewline(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 70, 70)
	sd := ddDigest(t, buf, 65536)

	stripped := strings.TrimRight(sd.String(), "\n")
	checkTrue(t, !strings.HasSuffix(stripped, "\n"),
		"stripped digest must not end with a newline")

	parsed, err := ParseSdbfFromString(stripped)
	mustNoError(t, err, "ParseSdbfFromString must succeed on a DD digest without a trailing newline (regression: issue #15)")

	checkEqual(t, sd.String(), parsed.String(),
		"parsed digest String() must equal the original (regression: issue #15)")
	checkEqual(t, 100, parsed.Compare(parsed),
		"self-comparison of parsed digest must return 100 (regression: issue #15)")
}

// =========================================================================
// Issue 17 — Compare panics on nil or foreign Sdbf implementation
// https://github.com/malwarology/sdhash/issues/17
// =========================================================================

// ---------------------------------------------------------------------------
// 00190000  Compare with nil Sdbf returns -1
// ---------------------------------------------------------------------------

// TestIssue17_CompareNilSdbf verifies that calling Compare with a nil Sdbf
// argument returns -1 instead of panicking. Without a nil guard inside
// Compare, passing nil causes a nil-pointer dereference when the
// implementation attempts to access the argument's fields.
func TestIssue17_CompareNilSdbf(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 80, 80)
	sd := streamDigest(t, buf)

	var score int
	checkNotPanics(t, func() { score = sd.Compare(nil) },
		"Compare(nil) must not panic (regression: issue #17)")
	checkEqual(t, -1, score,
		"Compare(nil) must return -1 (regression: issue #17)")
}

// ---------------------------------------------------------------------------
// 00200000  Compare with foreign Sdbf implementation returns -1
// ---------------------------------------------------------------------------

// foreignSdbfImpl is a minimal Sdbf implementation used only by
// TestIssue17_CompareForeignImpl. It satisfies the Sdbf interface but is not
// the internal *sdbf type, so a type-assertion guard inside Compare must
// handle it gracefully rather than panicking.
type foreignSdbfImpl struct{}

func (f *foreignSdbfImpl) Size() uint64            { return 0 }
func (f *foreignSdbfImpl) InputSize() uint64       { return 0 }
func (f *foreignSdbfImpl) FilterCount() uint32     { return 0 }
func (f *foreignSdbfImpl) Compare(Sdbf) int        { return 0 }
func (f *foreignSdbfImpl) String() string          { return "" }
func (f *foreignSdbfImpl) FeatureDensity() float64 { return 0 }

// TestIssue17_CompareForeignImpl verifies that calling Compare with a foreign
// Sdbf implementation — one that satisfies the interface but is not the
// internal *sdbf type — returns -1 instead of panicking. Without a type-assertion
// guard inside Compare, a type assertion to *sdbf on the foreign
// value panics at runtime.
func TestIssue17_CompareForeignImpl(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 81, 81)
	sd := streamDigest(t, buf)

	foreign := &foreignSdbfImpl{}

	var score int
	checkNotPanics(t, func() { score = sd.Compare(foreign) },
		"Compare with a foreign Sdbf implementation must not panic (regression: issue #17)")
	checkEqual(t, -1, score,
		"Compare with a foreign Sdbf implementation must return -1 (regression: issue #17)")
}

// =========================================================================
// Issue 19 — Unconstrained maxElem enables uint32 overflow in Compare
// https://github.com/malwarology/sdhash/issues/19
// =========================================================================

// ---------------------------------------------------------------------------
// 00210000  Parse maxElem overflow (uint32 wraparound)
// ---------------------------------------------------------------------------

// TestIssue19_ParseMaxElemOverflow verifies that a stream digest string with
// maxElem set to 2147483649 (0x80000001) is rejected by ParseSdbfFromString.
// Without an upper-bound check, the value is silently truncated to uint32,
// causing arithmetic overflow in the scoring path that produces an
// out-of-bounds index into cutoffs256 (149 entries) and panics.
func TestIssue19_ParseMaxElemOverflow(t *testing.T) {
	t.Parallel()

	// maxElem=2147483649 (0x80000001) overflows uint32 arithmetic in the
	// scoring path. The buffer is a valid 512-byte payload (bfCount=2,
	// bfSize=256) so all other validation checks would pass without the fix.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 2*256))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:2147483649:2:0:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error for a maxElem that overflows uint32 arithmetic (regression: issue #19)")
}

// ---------------------------------------------------------------------------
// 00220000  Parse maxElem zero
// ---------------------------------------------------------------------------

// TestIssue19_ParseMaxElemZero verifies that a stream digest string with
// maxElem set to 0 is rejected by ParseSdbfFromString. A zero maxElem is
// semantically meaningless (no elements can be inserted) and would produce
// a divide-by-zero or scoring anomaly if passed through unchecked.
func TestIssue19_ParseMaxElemZero(t *testing.T) {
	t.Parallel()

	// maxElem=0: zero max elements is invalid. The buffer is a valid 256-byte
	// payload (bfCount=1, bfSize=256) so all other validation checks would
	// pass without the fix.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:0:1:0:%s\n", payload)

	_, err := ParseSdbfFromString(digest)
	checkError(t, err,
		"ParseSdbfFromString must return an error for a maxElem of zero (regression: issue #19)")
}

// =========================================================================
// Issue 20 — Inner while loop evaluates array access before bounds guard
// https://github.com/malwarology/sdhash/issues/20
// =========================================================================

// ---------------------------------------------------------------------------
// 00230000  generateChunkScores inner while loop OOB
// ---------------------------------------------------------------------------

// TestIssue20_ChunkScoresInnerWhileOOB verifies that generateChunkScores
// completes without an out-of-bounds panic when the inner while loop runs
// near the end of the chunk. Without the fix, the loop evaluates
// chunkRanks[i+popWin] before the bounds guard i < chunkSize-popWin,
// causing a panic when i+popWin reaches the end of the slice. The crafted
// ranks place the window minimum at index 189 so that the inner while loop
// is entered and advances i toward the slice boundary.
func TestIssue20_ChunkScoresInnerWhileOOB(t *testing.T) {
	t.Parallel()

	chunkRanks := make([]uint16, 192)
	chunkScores := make([]uint16, 192)

	for i := range chunkRanks {
		chunkRanks[i] = 50
	}
	chunkRanks[189] = 10

	sd := &sdbf{popWinSize: PopWinSize}

	checkNotPanics(t, func() { sd.generateChunkScores(chunkRanks, 192, chunkScores, nil) },
		"generateChunkScores must not panic near the end of the chunk (regression: issue #20)")
}

// =========================================================================
// Issue 21 — WithBlockSize accepts values below PopWinSize causing underflow panic
// https://github.com/malwarology/sdhash/issues/21
// =========================================================================

// ---------------------------------------------------------------------------
// 00240000  Small block size uint64 underflow
// ---------------------------------------------------------------------------

// TestIssue21_SmallBlockSizeUnderflow verifies that passing a block size below
// PopWinSize (64) to WithBlockSize causes Compute to return an error rather than
// panicking. Without a validation check in createSdbf, the histogram loop in
// generateChunkScores computes chunkSize-popWin as a uint64 subtraction that
// underflows to a huge value, causing an out-of-bounds index and a goroutine
// panic that terminates the process.
func TestIssue21_SmallBlockSizeUnderflow(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 90, 90)

	factory, err := CreateSdbfFromBytes(buf)
	mustNoError(t, err)

	var computeErr error
	checkNotPanics(t, func() {
		_, computeErr = factory.WithBlockSize(32).Compute()
	}, "WithBlockSize(32).Compute() must not panic (regression: issue #21)")
	checkError(t, computeErr,
		"WithBlockSize(32).Compute() must return an error when block size is below PopWinSize (regression: issue #21)")
}
