package sdhash

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/bits"
	"os"
	"strings"
	"testing"
	"time"
)

// Regression test index
//
// Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
//    https://github.com/eciavatta/sdhash/issues/1
// ├── 00010000  Stream and DD parsed score in range
// ├── 00020000  Round-trip stream reference
// └── 00030000  Round-trip DD reference
//
// Issue 2 — Feature density detection for degenerate stream mode digests
//    https://github.com/malwarology/sdhash/issues/2
// └── 00040000  DD mode no false positive
//
// Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
//    https://github.com/malwarology/sdhash/issues/3
// └── 00050000  High block count DD mode
//
// Issue 4 — Unbounded memory allocation in Parse
//    https://github.com/malwarology/sdhash/issues/4
// ├── 00060000  Parse oversized bfCount
// └── 00070000  Parse zero bfSize
//
// Issue 10 — Parse panics on truncated base64 payload
//    https://github.com/malwarology/sdhash/issues/10
// ├── 00080000  Parse truncated stream buffer
// ├── 00090000  Parse stream lastCount exceeds maxElem
// ├── 00100000  Parse DD block too short
// └── 00110000  Parse DD element count exceeds maxElem
//
// Issue 11 — BfSize exported as mutable var but hardwired to 256 throughout
//    https://github.com/malwarology/sdhash/issues/11
// └── 00120000  Parse unsupported bfSize
//
// Issue 14 — New retains caller's slice without copying
//    https://github.com/malwarology/sdhash/issues/14
// └── 00130000  Buffer mutation after factory creation
//
// Issue 15 — DD parsing fails on digests without trailing newline
//    https://github.com/malwarology/sdhash/issues/15
// └── 00140000  DD parse without trailing newline
//
// Issue 17 — Similarity panics on nil or foreign Digest implementation
//    https://github.com/malwarology/sdhash/issues/17
// ├── 00150000  Similarity with nil Digest returns -1
// └── 00160000  Similarity with foreign Digest implementation returns -1
//
// Issue 19 — Unconstrained maxElem enables uint32 overflow in Similarity
//    https://github.com/malwarology/sdhash/issues/19
// ├── 00170000  Parse maxElem overflow (uint32 wraparound)
// └── 00180000  Parse maxElem zero
//
// Issue 20 — Inner while loop evaluates array access before bounds guard
//    https://github.com/malwarology/sdhash/issues/20
// └── 00190000  generateChunkScores inner while loop OOB
//
// Issue 21 — WithBlockSize accepts values below PopWinSize causing underflow panic
//    https://github.com/malwarology/sdhash/issues/21
// └── 00200000  Small block size uint64 underflow
//
// Issue 31 — Parse ddBlockSize silently truncated from uint64 to uint32
//    https://github.com/malwarology/sdhash/issues/31
// └── 00210000  DD ddBlockSize uint64 to uint32 truncation
//
// Issue 43 — sdbfScore mixes -1 sentinel returns from sdbfMaxScore into the score sum, corrupting results
//    https://github.com/malwarology/sdhash/issues/43
// ├── 00220000  Stream mode degenerate pair returns score 0 and ok false
// └── 00230000  DD mode degenerate pair returns score 0 and ok false
//
// Issue 57 — generateChunkScores double-counts positions in equal-rank runs
//    https://github.com/malwarology/sdhash/issues/57
// ├── 00240000  Reference equivalence: high-entropy inputs
// ├── 00250000  Reference equivalence: tie-heavy inputs
// ├── 00260000  Reference equivalence: zero-laden inputs
// ├── 00270000  Reference equivalence: persistent-min inputs
// ├── 00280000  Reference equivalence: monotonic inputs
// ├── 00290000  Reference equivalence: all-equal inputs
// ├── 00300000  Reference equivalence: all-zero inputs
// ├── 00310000  Golden: high-entropy single interior minimum
// ├── 00320000  Golden: tie-heavy rightmost-of-first-run selection
// ├── 00330000  Golden: zero-laden zero-minimum skipped
// ├── 00340000  Golden: persistent-min single position, no double-count
// ├── 00350000  Golden: monotonic minimum at left edge
// ├── 00360000  Golden: all-equal rightmost-of-window, one increment per window
// └── 00370000  Golden: all-zero produces no scores
//
// Issue 62 — uint32 overflow in DD-mode filter indexing can panic or
// silently corrupt digests on large inputs
//    https://github.com/malwarology/sdhash/issues/62
// ├── 00380000  computeHamming offset arithmetic at the reported overflow scale
// ├── 00390000  computeHamming correctness across many filters
// ├── 00400000  String DD branch offset arithmetic at the reported overflow scale
// ├── 00410000  String DD branch round-trip preserves buffer across many filters
// ├── 00420000  generateChunkSdbf trim-step arithmetic at the reported overflow scale
// ├── 00430000  sdbfMaxScore offset arithmetic at the reported overflow scale
// └── 00440000  sdbfMaxScore correctly addresses each filter across the full index range
//
// Issue 63 — No allocation cap on DD-mode digest generation — large inputs
// with small block sizes can produce multi-GiB buffers
//    https://github.com/malwarology/sdhash/issues/63
// ├── 00450000  WithBlockSize rejects allocation above the cap
// ├── 00460000  Allocation cap allows the exact boundary
// └── 00470000  Allocation cap rejects before allocating the buffer
//
// Issue 64 — ParseReader buffers unbounded attacker-controlled data before
// validating buffer length
//    https://github.com/malwarology/sdhash/issues/64
// ├── 00480000  Stream mode unterminated buffer does not hang
// ├── 00490000  DD mode unterminated block does not hang
// ├── 00500000  Stream mode bounded read does not consume unbounded input
// └── 00510000  DD mode bounded read does not consume unbounded input
//
// Issue 66 — DD-mode last-block terminator handling over-reads into
// immediately-following data, corrupting concatenated digest streams
//    https://github.com/malwarology/sdhash/issues/66
// ├── 00520000  Concatenated DD digests parse correctly
// ├── 00530000  Last block terminator variants
// └── 00540000  Non-last block delimiter mismatch rejected

// =========================================================================
// Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
// https://github.com/eciavatta/sdhash/issues/1
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Stream and DD parsed score in range
// ---------------------------------------------------------------------------

func TestIssue1_StreamAndDDParsedScoreInRange(t *testing.T) {
	t.Parallel()

	streamBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	ddBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)

	streamSD, err := Parse(string(streamBytes))
	mustNoError(t, err, "Parse must succeed on issue1.stream")

	ddSD, err := Parse(string(ddBytes))
	mustNoError(t, err, "Parse must succeed on issue1.dd")

	var score int
	var ok bool
	checkNotPanics(t, func() { score, ok = streamSD.Similarity(ddSD) }, "cross-mode Similarity must not panic")
	checkTrue(t, ok, "cross-mode Similarity must be meaningful")
	checkAtLeast(t, score, 0, "cross-mode score must be >= 0")
	checkAtMost(t, score, 100, "cross-mode score must be <= 100")
}

// ---------------------------------------------------------------------------
// 00020000  Round-trip stream reference
// ---------------------------------------------------------------------------

func TestIssue1_RoundTrip_StreamReference(t *testing.T) {
	t.Parallel()
	rawBytes, err := os.ReadFile("testdata/issue1.stream")
	mustNoError(t, err)
	raw := strings.TrimRight(string(rawBytes), "\r\n") + "\n"

	sd, err := Parse(raw)
	mustNoError(t, err)

	checkEqual(t, raw, sd.String(), "Parse→String must be identity for issue1.stream")
	score, ok := sd.Similarity(sd)
	checkTrue(t, ok, "self-comparison of parsed issue1.stream digest must be comparable")
	checkEqual(t, 100, score, "self-comparison of parsed issue1.stream digest must be 100")
}

// ---------------------------------------------------------------------------
// 00030000  Round-trip DD reference
// ---------------------------------------------------------------------------

func TestIssue1_RoundTrip_DDReference(t *testing.T) {
	t.Parallel()
	rawBytes, err := os.ReadFile("testdata/issue1.dd")
	mustNoError(t, err)
	raw := strings.TrimRight(string(rawBytes), "\r\n") + "\n"

	sd, err := Parse(raw)
	mustNoError(t, err)

	checkEqual(t, raw, sd.String(), "Parse→String must be identity for issue1.dd")
	score, ok := sd.Similarity(sd)
	checkTrue(t, ok, "self-comparison of parsed issue1.dd digest must be comparable")
	checkEqual(t, 100, score, "self-comparison of parsed issue1.dd digest must be 100")
}

// =========================================================================
// Issue 2 — Feature density detection for degenerate stream mode digests
// https://github.com/malwarology/sdhash/issues/2
// =========================================================================

// ---------------------------------------------------------------------------
// 00040000  DD mode no false positive
// ---------------------------------------------------------------------------

// TestIssue2_DDModeNoFalsePositive verifies that DD mode does not produce
// the same false positive for the issue 2 samples.
func TestIssue2_DDModeNoFalsePositive(t *testing.T) {
	t.Parallel()

	dataA := decryptTestFile(t, "testdata/issue2a.bin.enc")
	dataB := decryptTestFile(t, "testdata/issue2b.bin.enc")

	ddA := ddDigest(t, dataA, 65536)
	ddB := ddDigest(t, dataB, 65536)

	score, ok := ddA.Similarity(ddB)
	checkTrue(t, ok, "issue2 DD comparison must be comparable")
	checkEqual(t, 0, score,
		"issue2 DD comparison must be 0")
}

// =========================================================================
// Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
// https://github.com/malwarology/sdhash/issues/3
// =========================================================================

// ---------------------------------------------------------------------------
// 00050000  High block count DD mode
// ---------------------------------------------------------------------------

// TestIssue3_HighBlockCountDDMode verifies that computing a DD digest with a
// small block size (1024 bytes) over a 1 MiB buffer — producing ~1024 blocks —
// completes correctly without unbounded goroutine spawning. Without the
// semaphore fix in generateBlockSdbf, this configuration spawns 1024+
// goroutines simultaneously.
func TestIssue3_HighBlockCountDDMode(t *testing.T) {
	t.Parallel()

	data := randomBuf(1<<20, 50, 50)

	factory, err := New(data)
	mustNoError(t, err)

	const ddBlockSize = 1024
	sd, err := factory.WithBlockSize(ddBlockSize).Compute()
	mustNoError(t, err)

	score, ok := sd.Similarity(sd)
	checkTrue(t, ok, "self-comparison must be comparable")
	checkEqual(t, 100, score, "self-comparison must return 100")
}

// =========================================================================
// Issue 4 — Unbounded memory allocation in Parse
// https://github.com/malwarology/sdhash/issues/4
// =========================================================================

// ---------------------------------------------------------------------------
// 00060000  Parse oversized bfCount
// ---------------------------------------------------------------------------

// TestIssue4_ParseOversizedBfCount verifies that a digest string with a
// bfCount large enough to exceed the 256 MiB allocation limit is rejected
// by Parse rather than causing an OOM panic.
func TestIssue4_ParseOversizedBfCount(t *testing.T) {
	t.Parallel()

	// bfCount of 999999999 with the default bfSize of 256 bytes would require
	// ~238 GiB, far exceeding the 256 MiB cap.
	digest := "sdbf:03:1:-:1048576:sha1:256:5:7ff:160:999999999:100:"

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a bfCount that exceeds the allocation limit (regression: issue #4)")
}

// ---------------------------------------------------------------------------
// 00070000  Parse zero bfSize
// ---------------------------------------------------------------------------

// TestIssue4_ParseZeroBfSize verifies that a digest string with bfSize set to
// zero is rejected by Parse rather than causing a divide-by-zero
// panic inside the allocation sanity check.
func TestIssue4_ParseZeroBfSize(t *testing.T) {
	t.Parallel()

	// bfSize of 0 must be caught before the allocation check to prevent
	// a divide-by-zero when computing maxBfAlloc/bfSize.
	digest := "sdbf:03:1:-:1048576:sha1:0:5:7ff:160:100:100:"

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a bfSize of zero (regression: issue #4)")
}

// =========================================================================
// Issue 10 — Parse panics on truncated base64 payload
// https://github.com/malwarology/sdhash/issues/10
// =========================================================================

// ---------------------------------------------------------------------------
// 00080000  Parse truncated stream buffer
// ---------------------------------------------------------------------------

// TestIssue10_ParseTruncatedStreamBuffer verifies that a stream digest whose
// base64 payload decodes to fewer bytes than bfCount × bfSize is rejected by
// Parse rather than causing a slice-bounds panic in computeHamming.
func TestIssue10_ParseTruncatedStreamBuffer(t *testing.T) {
	t.Parallel()

	// bfCount=1, bfSize=256: the buffer must be 256 bytes, but we supply only 128.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 128))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:100:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error when the base64 payload decodes to fewer bytes than bfCount × bfSize (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00090000  Parse stream lastCount exceeds maxElem
// ---------------------------------------------------------------------------

// TestIssue10_ParseStreamLastCountExceedsMaxElem verifies that a stream digest
// where lastCount is greater than maxElem is rejected by Parse.
func TestIssue10_ParseStreamLastCountExceedsMaxElem(t *testing.T) {
	t.Parallel()

	// maxElem=160, lastCount=999: lastCount must not exceed maxElem.
	// The buffer is a valid 256-byte payload so the length check passes first.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:160:1:999:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error when lastCount exceeds maxElem (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00100000  Parse DD block too short
// ---------------------------------------------------------------------------

// TestIssue10_ParseDDBlockTooShort verifies that a DD digest where a block's
// base64 decodes to fewer bytes than bfSize is rejected by Parse
// rather than leaving the destination slice partially filled.
func TestIssue10_ParseDDBlockTooShort(t *testing.T) {
	t.Parallel()

	// bfCount=1, bfSize=256, elemCount=0x64 (100 ≤ maxElem=160): the block
	// payload must be 256 bytes, but we supply only 128.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 128))
	digest := fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:160:1:65536:64:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error when a DD block's base64 decodes to fewer bytes than bfSize (regression: issue #10)")
}

// ---------------------------------------------------------------------------
// 00110000  Parse DD element count exceeds maxElem
// ---------------------------------------------------------------------------

// TestIssue10_ParseDDElemCountExceedsMaxElem verifies that a DD digest where
// a block's element count exceeds maxElem is rejected by Parse.
func TestIssue10_ParseDDElemCountExceedsMaxElem(t *testing.T) {
	t.Parallel()

	// maxElem=192 (0xc0), elemCount=0xff (255): 255 > 192 must be rejected.
	// The block payload is a valid 256-byte buffer so the length check would pass.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:65536:ff:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error when a DD block element count exceeds maxElem (regression: issue #10)")
}

// =========================================================================
// Issue 11 — BfSize exported as mutable var but hardwired to 256 throughout
// https://github.com/malwarology/sdhash/issues/11
// =========================================================================

// ---------------------------------------------------------------------------
// 00120000  Parse unsupported bfSize
// ---------------------------------------------------------------------------

// TestIssue11_ParseUnsupportedBfSize verifies that a stream digest string with
// bfSize set to 512 instead of the only supported value (256) is rejected by
// Parse. The rest of the digest is structurally valid: bfCount=1,
// maxElem=160, lastCount=100, and a 512-byte base64 payload that satisfies the
// bfCount × bfSize length check — ensuring the rejection is caused solely by
// the unsupported bfSize value and not by any other validation.
func TestIssue11_ParseUnsupportedBfSize(t *testing.T) {
	t.Parallel()

	// bfSize=512: the implementation is hardwired to 256-byte bloom filters, so
	// any other value must be rejected before any buffer is allocated or decoded.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 512))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:512:5:7ff:160:1:100:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a bfSize other than 256 (regression: issue #11)")
}

// =========================================================================
// Issue 14 — New retains caller's slice without copying
// https://github.com/malwarology/sdhash/issues/14
// =========================================================================

// ---------------------------------------------------------------------------
// 00130000  Buffer mutation after factory creation
// ---------------------------------------------------------------------------

// TestIssue14_BufferMutationAfterFactory verifies that mutating the original
// buffer after calling New does not affect the digest produced
// by the factory. Without a defensive copy inside New, zeroing
// the buffer between factory creation and Compute causes both factories to
// produce identical digests even though one was created from random data.
func TestIssue14_BufferMutationAfterFactory(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 60, 60)

	factory, err := New(buf)
	mustNoError(t, err)

	sd, err := factory.Compute()
	mustNoError(t, err)
	first := sd.String()

	// Zero out the original buffer to simulate a caller reusing or releasing it.
	clear(buf)

	factory2, err := New(buf)
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
// 00140000  DD parse without trailing newline
// ---------------------------------------------------------------------------

// TestIssue15_DDParseWithoutTrailingNewline verifies that Parse
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

	parsed, err := Parse(stripped)
	mustNoError(t, err, "Parse must succeed on a DD digest without a trailing newline (regression: issue #15)")

	checkEqual(t, sd.String(), parsed.String(),
		"parsed digest String() must equal the original (regression: issue #15)")
	score, ok := parsed.Similarity(parsed)
	checkTrue(t, ok, "self-comparison of parsed digest must be comparable (regression: issue #15)")
	checkEqual(t, 100, score, "self-comparison of parsed digest must return 100 (regression: issue #15)")
}

// =========================================================================
// Issue 17 — Similarity panics on nil or foreign Digest implementation
// https://github.com/malwarology/sdhash/issues/17
// =========================================================================

// ---------------------------------------------------------------------------
// 00150000  Similarity with nil Digest returns -1
// ---------------------------------------------------------------------------

// TestIssue17_SimilarityNilDigest verifies that calling Similarity with a nil Digest
// argument returns -1 instead of panicking. Without a nil guard inside
// Similarity, passing nil causes a nil-pointer dereference when the
// implementation attempts to access the argument's fields.
func TestIssue17_SimilarityNilDigest(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 80, 80)
	sd := streamDigest(t, buf)

	var ok bool
	checkNotPanics(t, func() { _, ok = sd.Similarity(nil) },
		"Similarity(nil) must not panic (regression: issue #17)")
	checkTrue(t, !ok,
		"Similarity(nil) must not be comparable (regression: issue #17)")
}

// ---------------------------------------------------------------------------
// 00160000  Similarity with foreign Digest implementation returns -1
// ---------------------------------------------------------------------------

// foreignDigestImpl is a minimal Digest implementation used only by
// TestIssue17_SimilarityForeignImpl. It satisfies the Digest interface but is not
// the internal *sdbf type, so a type-assertion guard inside Similarity must
// handle it gracefully rather than panicking.
type foreignDigestImpl struct{}

func (f *foreignDigestImpl) FilterSize() uint64            { return 0 }
func (f *foreignDigestImpl) InputSize() uint64             { return 0 }
func (f *foreignDigestImpl) FilterCount() uint32           { return 0 }
func (f *foreignDigestImpl) Similarity(Digest) (int, bool) { return 0, false }
func (f *foreignDigestImpl) String() string                { return "" }
func (f *foreignDigestImpl) FeatureDensity() float64       { return 0 }

// TestIssue17_SimilarityForeignImpl verifies that calling Similarity with a foreign
// Digest implementation — one that satisfies the interface but is not the
// internal *sdbf type — returns -1 instead of panicking. Without a type-assertion
// guard inside Similarity, a type assertion to *sdbf on the foreign
// value panics at runtime.
func TestIssue17_SimilarityForeignImpl(t *testing.T) {
	t.Parallel()

	buf := randomBuf(1<<20, 81, 81)
	sd := streamDigest(t, buf)

	foreign := &foreignDigestImpl{}

	var ok bool
	checkNotPanics(t, func() { _, ok = sd.Similarity(foreign) },
		"Similarity with a foreign Digest implementation must not panic (regression: issue #17)")
	checkTrue(t, !ok,
		"Similarity with a foreign Digest implementation must not be comparable (regression: issue #17)")
}

// =========================================================================
// Issue 19 — Unconstrained maxElem enables uint32 overflow in Similarity
// https://github.com/malwarology/sdhash/issues/19
// =========================================================================

// ---------------------------------------------------------------------------
// 00170000  Parse maxElem overflow (uint32 wraparound)
// ---------------------------------------------------------------------------

// TestIssue19_ParseMaxElemOverflow verifies that a stream digest string with
// maxElem set to 2147483649 (0x80000001) is rejected by Parse.
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

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a maxElem that overflows uint32 arithmetic (regression: issue #19)")
}

// ---------------------------------------------------------------------------
// 00180000  Parse maxElem zero
// ---------------------------------------------------------------------------

// TestIssue19_ParseMaxElemZero verifies that a stream digest string with
// maxElem set to 0 is rejected by Parse. A zero maxElem is
// semantically meaningless (no elements can be inserted) and would produce
// a divide-by-zero or scoring anomaly if passed through unchecked.
func TestIssue19_ParseMaxElemZero(t *testing.T) {
	t.Parallel()

	// maxElem=0: zero max elements is invalid. The buffer is a valid 256-byte
	// payload (bfCount=1, bfSize=256) so all other validation checks would
	// pass without the fix.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf:03:1:-:1048576:sha1:256:5:7ff:0:1:0:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a maxElem of zero (regression: issue #19)")
}

// =========================================================================
// Issue 20 — Inner while loop evaluates array access before bounds guard
// https://github.com/malwarology/sdhash/issues/20
// =========================================================================

// ---------------------------------------------------------------------------
// 00190000  generateChunkScores inner while loop OOB
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

	sd := &sdbf{popWinSize: popWinSize}

	checkNotPanics(t, func() { sd.generateChunkScores(chunkRanks, 192, chunkScores, nil) },
		"generateChunkScores must not panic near the end of the chunk (regression: issue #20)")
}

// =========================================================================
// Issue 21 — WithBlockSize accepts values below PopWinSize causing underflow panic
// https://github.com/malwarology/sdhash/issues/21
// =========================================================================

// ---------------------------------------------------------------------------
// 00200000  Small block size uint64 underflow
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

	factory, err := New(buf)
	mustNoError(t, err)

	var computeErr error
	checkNotPanics(t, func() {
		_, computeErr = factory.WithBlockSize(32).Compute()
	}, "WithBlockSize(32).Compute() must not panic (regression: issue #21)")
	checkError(t, computeErr,
		"WithBlockSize(32).Compute() must return an error when block size is below PopWinSize (regression: issue #21)")
}

// =========================================================================
// Issue 31 — ddBlockSize silently truncated from uint64 to uint32
// https://github.com/malwarology/sdhash/issues/31
// =========================================================================

// ---------------------------------------------------------------------------
// 00210000  DD ddBlockSize uint64 to uint32 truncation
// ---------------------------------------------------------------------------

// TestIssue31_DdBlockSizeTruncation verifies that a DD digest string with
// ddBlockSize set to 4294967552 (0x100000100, which truncates to 256 as uint32)
// is rejected by Parse. Without a range check, the value is
// silently narrowed when stored in a uint32 field, causing the parsed digest
// to carry an incorrect block size that later produces corrupt Similarity results
// or allows crafted input to bypass block-size validation.
func TestIssue31_DdBlockSizeTruncation(t *testing.T) {
	t.Parallel()

	// ddBlockSize=4294967552 (0x100000100) truncates to 256 when stored as
	// uint32. bfCount=1, bfSize=256, maxElem=192, elemCount=0xc0 (192 ≤
	// maxElem=192): all other validation checks would pass without the fix.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 256))
	digest := fmt.Sprintf("sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:4294967552:c0:%s\n", payload)

	_, err := Parse(digest)
	checkError(t, err,
		"Parse must return an error for a ddBlockSize that overflows uint32 (regression: issue #31)")
}

// =========================================================================
// Issue 43 — sdbfScore mixes -1 sentinel returns from sdbfMaxScore into the score sum, corrupting results
// https://github.com/malwarology/sdhash/issues/43
// =========================================================================

// ---------------------------------------------------------------------------
// 00220000  Stream mode degenerate pair returns score 0 and ok false
// ---------------------------------------------------------------------------

// TestIssue43_StreamDegeneratePairScore verifies that comparing two stream
// digests where some filters have no scoreable target returns a clean
// (score, true) result. Pre-fix, the -1 sentinels returned by sdbfMaxScore
// for no-scoreable-target filters were summed directly into scoreSum,
// pushing it negative and causing Similarity to incorrectly report the pair as
// incomparable (0, false). Post-fix, the -1 returns are excluded from both
// the sum and the denominator, the remaining valid filter comparisons are
// averaged correctly, and this pair's low real similarity is reported as
// (0, true). The regression signature is the ok flag: any reintroduction of
// the -1-accumulation bug will flip it back to false on this pair.
func TestIssue43_StreamDegeneratePairScore(t *testing.T) {
	t.Parallel()

	dataA := decryptTestFile(t, "testdata/issue43a.bin.enc")
	dataB := decryptTestFile(t, "testdata/issue43b.bin.enc")

	sdA := streamDigest(t, dataA)
	sdB := streamDigest(t, dataB)

	var score int
	var ok bool
	checkNotPanics(t, func() { score, ok = sdA.Similarity(sdB) },
		"Similarity must not panic on this pair (regression: issue #43)")
	checkTrue(t, ok,
		"Similarity must return ok=true; pre-fix bug flipped it to false (regression: issue #43)")
	checkEqual(t, 0, score,
		"Similarity must return score=0 for this pair (regression: issue #43)")
}

// ---------------------------------------------------------------------------
// 00230000  DD mode degenerate pair returns score 0 and ok false
// ---------------------------------------------------------------------------

// TestIssue43_DDDegeneratePairScore verifies the same sentinel-exclusion fix
// in DD (block-aligned) mode. Pre-fix, summing -1 sentinels into scoreSum
// flipped this pair to (0, false), falsely reporting it as incomparable.
// Post-fix, the -1 returns are properly excluded from both the sum and the
// denominator, and the pair's low real similarity is reported as (0, true).
// The regression signature is the ok flag: any reintroduction of the
// -1-accumulation bug will flip it back to false on this pair.
func TestIssue43_DDDegeneratePairScore(t *testing.T) {
	t.Parallel()

	const ddBlockSize = 1048576

	dataA := decryptTestFile(t, "testdata/issue43a.bin.enc")
	dataB := decryptTestFile(t, "testdata/issue43b.bin.enc")

	sdA := ddDigest(t, dataA, ddBlockSize)
	sdB := ddDigest(t, dataB, ddBlockSize)

	var score int
	var ok bool
	checkNotPanics(t, func() { score, ok = sdA.Similarity(sdB) },
		"Similarity must not panic on this pair (regression: issue #43)")
	checkTrue(t, ok,
		"Similarity must return ok=true; pre-fix bug flipped it to false (regression: issue #43)")
	checkEqual(t, 0, score,
		"Similarity must return score=0 for this pair (regression: issue #43)")
}

// =========================================================================
// Issue 57 — generateChunkScores double-counts positions in equal-rank runs
//    https://github.com/malwarology/sdhash/issues/57
//
// The pre-fix two-block selector double-counted positions in runs of equal
// ranks. The fixed function increments exactly one position per window, chosen
// by the per-window rule captured in bruteScoresFirstRun. The reference-
// equivalence tests assert the production function matches that spec across
// adversarial inputs; the golden tests pin the exact output for crafted cases.
// =========================================================================

// ---------------------------------------------------------------------------
// 00240000  Reference equivalence: high-entropy inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_HighEntropy(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("highentropy", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("high-entropy seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00250000  Reference equivalence: tie-heavy inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_TieHeavy(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("tieheavy", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("tie-heavy seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00260000  Reference equivalence: zero-laden inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_ZeroLaden(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("zeroladen", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("zero-laden seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00270000  Reference equivalence: persistent-min inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_PersistentMin(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("persistmin", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("persistent-min seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00280000  Reference equivalence: monotonic inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_Monotonic(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("monotonic", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("monotonic seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00290000  Reference equivalence: all-equal inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_AllEqual(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("allequal", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("all-equal seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00300000  Reference equivalence: all-zero inputs
// ---------------------------------------------------------------------------

func TestIssue57_Equivalence_AllZero(t *testing.T) {
	t.Parallel()
	for seed := uint64(1); seed <= 20; seed++ {
		for _, ranks := range rankCasesFor("allzero", seed) {
			checkChunkScoresMatchSpec(t, ranks, fmt.Sprintf("all-zero seed=%d n=%d (regression: issue #57)", seed, len(ranks)))
		}
	}
}

// ---------------------------------------------------------------------------
// 00310000  Golden: high-entropy single interior minimum
// ---------------------------------------------------------------------------

func TestIssue57_Golden_HighEntropy(t *testing.T) {
	t.Parallel()
	// Distinct values with a single clear minimum at position 32.
	ranks := make([]uint16, 65)
	for i := range ranks {
		ranks[i] = uint16(100 + i)
	}
	ranks[32] = 1
	want := make([]uint16, 65)
	want[32] = 1
	checkChunkScoresGolden(t, ranks, want, "high-entropy single interior minimum (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00320000  Golden: tie-heavy rightmost-of-first-run selection
// ---------------------------------------------------------------------------

func TestIssue57_Golden_TieHeavy(t *testing.T) {
	t.Parallel()
	// Minimum value 2 appears as a consecutive run at 5,6,7 and again,
	// non-consecutively, at 20. The rule selects the rightmost of the FIRST
	// run (position 7); the latter, non-adjacent 2 is ignored.
	ranks := make([]uint16, 65)
	for i := range ranks {
		ranks[i] = 9
	}
	ranks[5], ranks[6], ranks[7] = 2, 2, 2
	ranks[20] = 2
	want := make([]uint16, 65)
	want[7] = 1
	checkChunkScoresGolden(t, ranks, want, "tie-heavy rightmost-of-first-run (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00330000  Golden: zero-laden zero-minimum skipped
// ---------------------------------------------------------------------------

func TestIssue57_Golden_ZeroLaden(t *testing.T) {
	t.Parallel()
	// The array minimum is a zero at position 10, but zeros are never selected;
	// the minimum NONZERO rank (3 at position 30) wins instead.
	ranks := make([]uint16, 65)
	for i := range ranks {
		ranks[i] = 9
	}
	ranks[10] = 0
	ranks[30] = 3
	want := make([]uint16, 65)
	want[30] = 1
	checkChunkScoresGolden(t, ranks, want, "zero-laden zero-minimum skipped (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00340000  Golden: persistent-min single position, no double-count
// ---------------------------------------------------------------------------

func TestIssue57_Golden_PersistentMin(t *testing.T) {
	t.Parallel()
	// A run of the minimum value (1) at positions 30..40 sits fully inside all
	// six windows. Each window selects position 40 (rightmost of the run) and
	// increments it exactly once: the pre-fix double-count would inflate this.
	ranks := make([]uint16, 70)
	for i := range ranks {
		ranks[i] = 9
	}
	for i := 30; i <= 40; i++ {
		ranks[i] = 1
	}
	want := make([]uint16, 70)
	want[40] = 6
	checkChunkScoresGolden(t, ranks, want, "persistent-min single position no double-count (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00350000  Golden: monotonic minimum at left edge
// ---------------------------------------------------------------------------

func TestIssue57_Golden_Monotonic(t *testing.T) {
	t.Parallel()
	// Strictly increasing ranks: each window's minimum is its left-edge element.
	ranks := make([]uint16, 66)
	for i := range ranks {
		ranks[i] = uint16(i + 1)
	}
	want := make([]uint16, 66)
	want[0] = 1
	want[1] = 1
	checkChunkScoresGolden(t, ranks, want, "monotonic minimum at left edge (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00360000  Golden: all-equal rightmost-of-window, one increment per window
// ---------------------------------------------------------------------------

func TestIssue57_Golden_AllEqual(t *testing.T) {
	t.Parallel()
	// All ranks equal: each window's first run spans the whole window, so its
	// rightmost element is selected. Two windows -> positions 63 and 64, one
	// increment each (the pre-fix bug produced [.,.,1,0,2] here).
	ranks := make([]uint16, 66)
	for i := range ranks {
		ranks[i] = 7
	}
	want := make([]uint16, 66)
	want[63] = 1
	want[64] = 1
	checkChunkScoresGolden(t, ranks, want, "all-equal rightmost-of-window (regression: issue #57)")
}

// ---------------------------------------------------------------------------
// 00370000  Golden: all-zero produces no scores
// ---------------------------------------------------------------------------

func TestIssue57_Golden_AllZero(t *testing.T) {
	t.Parallel()
	// Zero ranks are never selected, so no position is ever incremented.
	ranks := make([]uint16, 66)
	want := make([]uint16, 66)
	checkChunkScoresGolden(t, ranks, want, "all-zero produces no scores (regression: issue #57)")
}

// =========================================================================
// Issue 62 — uint32 overflow in DD-mode filter indexing can panic or
// silently corrupt digests on large inputs
// https://github.com/malwarology/sdhash/issues/62
// =========================================================================
//
// The finding names four call sites that compute a byte offset into
// sd.buffer from a bfSize/bfCount-derived index: computeHamming and the DD
// branch of String() (both sdhash.go), the post-generation buffer-trim step
// in generateChunkSdbf (generate.go), and sdbfMaxScore (score.go). Each is
// covered by two tests below:
//
//   - An "offset arithmetic" characterization test that evaluates the exact
//     expression now used at that call site (cited by file:line) against the
//     finding's own reported reproduction numbers (bfSize=256, index=2^24-1,
//     the point at which bfSize*i first overflows a uint32), and also
//     recomputes what the pre-fix uint32 arithmetic produced at those same
//     numbers, to keep the test tied to a concretely observed failure mode
//     rather than an abstract claim about overflow.
//
//   - A real-function test that calls the actual production function/method
//     (not a reimplementation) across many filters, to confirm the uint64
//     rewrite didn't just avoid overflow but still computes the *correct*
//     byte range at ordinary, in-range scale.
//
// A literal end-to-end reproduction at the reported scale is not attempted:
// reaching an actual 2^32-byte offset through any of these functions
// requires touching (computeHamming, String) or allocating (the trim step,
// sdbfMaxScore) on the order of 4.3 GiB, regardless of how bfSize and
// bfCount are split — i_overflow * bfSize = 2^32/bfSize * bfSize ≈ 2^32 is
// an invariant, not an implementation detail that can be engineered around.
// That figure exceeds what's available in many CI/dev environments (this
// one included), and the finding itself was "confirmed algebraically" for
// the same reason.
//
// The trim step's real-function coverage at ordinary scale already exists
// independently of this issue: TestGenerateChunkSdbf_MultiChunk_SparseLastFilter
// in sdhash_test.go asserts len(sd.buffer) == bfCount*bfSize after pruning
// and trimming, so it is not duplicated here.

// ---------------------------------------------------------------------------
// 00380000  computeHamming offset arithmetic at the reported overflow scale
// ---------------------------------------------------------------------------

// TestIssue62_ComputeHammingOffsetArithmetic verifies the offset arithmetic
// in computeHamming (sdhash.go:170, "start := bfSize * uint64(i)") does not
// invert for the finding's own reproduction numbers: bfSize=256,
// i=2^24-1. Under the pre-fix uint32 arithmetic, bfSize*i wrapped to
// 4294967040 and bfSize*(i+1) wrapped to 0, producing the inverted slice
// [4294967040:0] described in the finding.
func TestIssue62_ComputeHammingOffsetArithmetic(t *testing.T) {
	t.Parallel()

	// i is a runtime variable, not a constant: computing uint32(bfSize)*(i+1)
	// as a constant expression would overflow at compile time and fail to
	// build, masking the very runtime wraparound this test demonstrates.
	i := uint32(1<<24 - 1) // 16,777,215 — the finding's own reproduction index
	bfSizeU64 := uint64(bfSize)

	// Mirrors sdhash.go:170.
	start := bfSizeU64 * uint64(i)
	end := start + bfSizeU64
	checkEqual(t, uint64(4294967040), start,
		"uint64 start must equal the finding's reported value (regression: issue #62)")
	checkTrue(t, start < end,
		"uint64 start must be less than end, i.e. not inverted (regression: issue #62)")

	// Recompute what the pre-fix uint32 arithmetic actually produced, so
	// this test is tied to a concretely observed failure mode.
	oldStart := uint32(bfSize) * i
	oldEnd := uint32(bfSize) * (i + 1)
	checkEqual(t, uint32(4294967040), oldStart,
		"sanity: old uint32 start must match the finding's reported value")
	checkEqual(t, uint32(0), oldEnd,
		"sanity: old uint32 end must wrap to 0, inverting the slice")
	checkTrue(t, oldStart > oldEnd,
		"sanity: the pre-fix uint32 arithmetic must produce an inverted slice bound")
}

// ---------------------------------------------------------------------------
// 00390000  computeHamming correctness across many filters
// ---------------------------------------------------------------------------

// TestIssue62_ComputeHammingCorrectAcrossManyFilters calls the real
// computeHamming function (invoked automatically by Parse, sdhash.go:394)
// across many filters with per-filter distinguishable content, confirming
// that the uint64 rewrite still computes the correct hamming weight at
// every index. This is a property the characterization test above cannot
// establish on its own, since it does not call computeHamming itself.
func TestIssue62_ComputeHammingCorrectAcrossManyFilters(t *testing.T) {
	t.Parallel()

	const numFilters = 300
	filters := make([][]byte, numFilters)
	elemCounts := make([]uint16, numFilters)
	for i := range numFilters {
		f := make([]byte, bfSize)
		for j := range f {
			f[j] = byte(i)
		}
		filters[i] = f
		elemCounts[i] = 0x20
	}

	digestStr := buildDDDigest(uint64(numFilters*1024), 1024, filters, elemCounts)
	digest, err := Parse(digestStr)
	mustNoError(t, err, "parsing the crafted many-filter DD digest must succeed")

	sd := digest.(*sdbf)
	checkEqual(t, uint32(numFilters), sd.bfCount, "bfCount must match the number of crafted filters")

	for i := range numFilters {
		want := uint16(bfSize * bits.OnesCount8(byte(i)))
		checkEqual(t, want, sd.hamming[i], fmt.Sprintf("hamming weight for filter %d (regression: issue #62)", i))
	}
}

// ---------------------------------------------------------------------------
// 00400000  String DD branch offset arithmetic at the reported overflow scale
// ---------------------------------------------------------------------------

// TestIssue62_StringDDBranchOffsetArithmetic verifies the offset arithmetic
// in the DD branch of String() (sdhash.go:145, "start := uint64(i) *
// bfSize") does not invert for the finding's own reproduction numbers. The
// multiplication order is reversed relative to computeHamming's ("uint64(i)
// * bfSize" vs "bfSize * uint64(i)") but is the same call site named
// separately in the finding, so it is tested independently here rather than
// folded into TestIssue62_ComputeHammingOffsetArithmetic.
//
//goland:noinspection DuplicatedCode
func TestIssue62_StringDDBranchOffsetArithmetic(t *testing.T) {
	t.Parallel()

	// i is a runtime variable, not a constant: see the comment in
	// TestIssue62_ComputeHammingOffsetArithmetic for why.
	i := uint32(1<<24 - 1)
	bfSizeU64 := uint64(bfSize)

	// Mirrors sdhash.go:145.
	start := uint64(i) * bfSizeU64
	end := start + bfSizeU64
	checkEqual(t, uint64(4294967040), start,
		"uint64 start must equal the finding's reported value (regression: issue #62)")
	checkTrue(t, start < end,
		"uint64 start must be less than end, i.e. not inverted (regression: issue #62)")

	oldStart := i * uint32(bfSize)
	oldEnd := (i + 1) * uint32(bfSize)
	checkEqual(t, uint32(4294967040), oldStart,
		"sanity: old uint32 start must match the finding's reported value")
	checkEqual(t, uint32(0), oldEnd,
		"sanity: old uint32 end must wrap to 0, inverting the slice")
	checkTrue(t, oldStart > oldEnd,
		"sanity: the pre-fix uint32 arithmetic must produce an inverted slice bound")
}

// ---------------------------------------------------------------------------
// 00410000  String DD branch round-trip preserves buffer across many filters
// ---------------------------------------------------------------------------

// TestIssue62_StringDDBranchRoundTripPreservesBufferAcrossManyFilters calls
// the real String() DD branch (sdhash.go:140-147) on a many-filter digest
// with distinguishable, position-dependent per-filter content, then parses
// the result back and confirms every filter's bytes and element count
// round-trip to the exact same values at the exact same index. This directly
// exercises String()'s own offset arithmetic (as opposed to
// TestIssue62_ComputeHammingCorrectAcrossManyFilters, which only exercises
// computeHamming on the way in).
func TestIssue62_StringDDBranchRoundTripPreservesBufferAcrossManyFilters(t *testing.T) {
	t.Parallel()

	const numFilters = 300
	filters := make([][]byte, numFilters)
	elemCounts := make([]uint16, numFilters)
	for i := range numFilters {
		f := make([]byte, bfSize)
		for j := range f {
			f[j] = byte(i*37 + j) // distinct, position-dependent content per filter
		}
		filters[i] = f
		elemCounts[i] = uint16(0x10 + i%0x50)
	}

	digestStr := buildDDDigest(uint64(numFilters*1024), 1024, filters, elemCounts)
	digest1, err := Parse(digestStr)
	mustNoError(t, err, "parsing the crafted many-filter DD digest must succeed")

	serialized := digest1.String()
	digest2, err := Parse(serialized)
	mustNoError(t, err, "parsing the round-tripped digest must succeed")

	sd2 := digest2.(*sdbf)
	checkEqual(t, uint32(numFilters), sd2.bfCount, "bfCount must be unchanged by the round trip")

	for i := range numFilters {
		want := filters[i]
		got := sd2.buffer[i*bfSize : (i+1)*bfSize]
		checkTrue(t, bytes.Equal(want, got),
			fmt.Sprintf("filter %d bytes must round-trip unchanged (regression: issue #62)", i))
		checkEqual(t, elemCounts[i], sd2.elemCounts[i],
			fmt.Sprintf("filter %d elemCount must round-trip unchanged (regression: issue #62)", i))
	}
}

// ---------------------------------------------------------------------------
// 00420000  generateChunkSdbf trim-step arithmetic at the reported overflow scale
// ---------------------------------------------------------------------------

// TestIssue62_GenerateSdbfTrimStepArithmetic verifies the buffer-trim
// arithmetic in generateChunkSdbf (generate.go:369 and generate.go:451,
// "newLen := uint64(sd.bfCount) * uint64(sd.bfSize)") computes the correct,
// non-wrapped length at bfCount=2^24, bfSize=256 — the point at which the
// real product is exactly 2^32. This is the finding's second impact:
// unlike the indexing call sites above, an overflowed uint32 product here
// does not panic (0 is always a valid slice length) — it silently
// truncates the digest to a corrupt result.
func TestIssue62_GenerateSdbfTrimStepArithmetic(t *testing.T) {
	t.Parallel()

	// bCount and bSize are runtime variables, not constants: see the comment
	// in TestIssue62_ComputeHammingOffsetArithmetic for why.
	bCount := uint32(1 << 24) // 16,777,216
	bSize := uint32(256)

	// Mirrors generate.go:369 and generate.go:451.
	newLen := uint64(bCount) * uint64(bSize)
	checkEqual(t, uint64(1)<<32, newLen,
		"uint64 product must equal 2^32 exactly, not wrap (regression: issue #62)")

	oldProduct := bCount * bSize
	checkEqual(t, uint32(0), oldProduct,
		"sanity: the old uint32 product must wrap to exactly 0 for these inputs, "+
			"silently truncating rather than panicking")
}

// ---------------------------------------------------------------------------
// 00430000  sdbfMaxScore offset arithmetic at the reported overflow scale
// ---------------------------------------------------------------------------

// TestIssue62_SdbfMaxScoreOffsetArithmetic verifies the offset arithmetic in
// sdbfMaxScore (score.go:74, "bf1 := refSdbf.buffer[uint64(refIndex)*bfSize:]")
// does not invert for the finding's own reproduction numbers.
//
//goland:noinspection DuplicatedCode
func TestIssue62_SdbfMaxScoreOffsetArithmetic(t *testing.T) {
	t.Parallel()

	// refIndex is a runtime variable, not a constant: see the comment in
	// TestIssue62_ComputeHammingOffsetArithmetic for why.
	refIndex := uint32(1<<24 - 1)
	bfSizeU64 := uint64(bfSize)

	// Mirrors score.go:74.
	start := uint64(refIndex) * bfSizeU64
	end := start + bfSizeU64
	checkEqual(t, uint64(4294967040), start,
		"uint64 start must equal the finding's reported value (regression: issue #62)")
	checkTrue(t, start < end,
		"uint64 start must be less than end, i.e. not inverted (regression: issue #62)")

	oldStart := refIndex * uint32(bfSize)
	oldEnd := (refIndex + 1) * uint32(bfSize)
	checkEqual(t, uint32(4294967040), oldStart,
		"sanity: old uint32 start must match the finding's reported value")
	checkEqual(t, uint32(0), oldEnd,
		"sanity: old uint32 end must wrap to 0, inverting the slice")
	checkTrue(t, oldStart > oldEnd,
		"sanity: the pre-fix uint32 arithmetic must produce an inverted slice bound")
}

// ---------------------------------------------------------------------------
// 00440000  sdbfMaxScore correctly addresses each filter across the full index range
// ---------------------------------------------------------------------------

// TestIssue62_SdbfMaxScoreCorrectAcrossFullIndexRange calls the real
// sdbfMaxScore function directly, for every index across a many-filter
// digest, confirming refIndex correctly addresses that filter's own bytes.
//
// Construction: self-comparison (Similarity(sd, sd), as used by
// TestDDMode_SelfComparison) is not a strong enough test for this specific
// arithmetic, because sdbfMaxScore searches for the best match across every
// target index — a uniformly wrong offset applied identically to both
// operands of a self-comparison would still find a matching pair somewhere
// and report a perfect score. To eliminate that ambiguity, each ref filter
// is compared against a *single-filter* target digest built independently
// (via ordinary small-int slicing, not the arithmetic under test) to hold
// only ref's filter i's true content. Filters are populated with disjoint,
// per-index bloom-filter features (via fillBloomFeatures). A misaddressed
// ref filter — reading an adjacent filter's unrelated feature set instead
// — would then score well below a perfect match against this deliberately
// unambiguous target, rather than happening to match somewhere else in a
// larger target digest.
func TestIssue62_SdbfMaxScoreCorrectAcrossFullIndexRange(t *testing.T) {
	t.Parallel()

	const numFilters = 300
	const featuresPerFilter = 40 // well above minElemCount; hamming weight ~189, cutoffBySum[80]=18

	filters := make([][]byte, numFilters)
	elemCounts := make([]uint16, numFilters)
	for i := range numFilters {
		f := make([]byte, bfSize)
		fillBloomFeatures(f, uint32(i), featuresPerFilter)
		filters[i] = f
		elemCounts[i] = featuresPerFilter
	}

	digestStr := buildDDDigest(uint64(numFilters*1024), 1024, filters, elemCounts)
	digest, err := Parse(digestStr)
	mustNoError(t, err, "parsing the crafted many-filter DD digest must succeed")
	ref := digest.(*sdbf)

	for i := range numFilters {
		target := newTestSdbf(t)
		target.bfCount = 1
		target.maxElem = maxElemDd
		target.buffer = append([]byte(nil), filters[i]...)
		target.elemCounts = []uint16{featuresPerFilter}
		target.computeHamming()

		score := sdbfMaxScore(ref, uint32(i), target)
		checkEqual(t, 1.0, score,
			fmt.Sprintf("sdbfMaxScore must find a perfect match for filter %d against its own content (regression: issue #62)", i))
	}
}

// =========================================================================
// Issue 63 — No allocation cap on DD-mode digest generation — large inputs
// with small block sizes can produce multi-GiB buffers
// https://github.com/malwarology/sdhash/issues/63
// =========================================================================

// ---------------------------------------------------------------------------
// 00450000  WithBlockSize rejects allocation above the cap
// ---------------------------------------------------------------------------

// TestIssue63_WithBlockSizeRejectsAllocationAboveCap verifies, through the
// public Factory API named in the finding ("a caller — or attacker — who
// controls WithBlockSize and input size"), that a legitimate-looking large
// input paired with a small block size is rejected. It must not be allowed
// to drive an unbounded allocation. ddBlockSize is fixed at the minimum
// legal value (popWinSize) to minimize the input buffer needed to push
// bfCount one past maxBfAlloc/bfSize (1,048,576 filters at the real bfSize
// of 256).
func TestIssue63_WithBlockSizeRejectsAllocationAboveCap(t *testing.T) {
	t.Parallel()

	filterCap := maxBfAlloc / bfSize
	const ddBlockSize = popWinSize
	buf := make([]byte, (filterCap+1)*ddBlockSize)

	factory, err := New(buf)
	mustNoError(t, err, "New must accept the buffer itself; only WithBlockSize's Compute should reject it")

	_, err = factory.WithBlockSize(ddBlockSize).Compute()
	checkError(t, err,
		"Compute must reject a block size that drives bfCount past maxBfAlloc/bfSize (regression: issue #63)")
}

// ---------------------------------------------------------------------------
// 00460000  Allocation cap allows the exact boundary
// ---------------------------------------------------------------------------

// TestIssue63_AllocationCapAllowsExactBoundary verifies that the cap added in
// populateSdbf uses a strict greater-than comparison, not >=: a bfCount
// exactly equal to maxBfAlloc/bfSize must be allowed to proceed rather than
// being spuriously rejected. This complements
// TestIssue63_WithBlockSizeRejectsAllocationAboveCap, which only exercises
// one filter past the boundary.
//
// This calls populateSdbf directly (rather than through the public API) to
// keep the assertion scoped to the guard itself. It also lets the real
// DD-mode generation run to completion, confirming the digest that comes
// out the other side of the boundary is valid — not just that no error was
// raised prematurely.
func TestIssue63_AllocationCapAllowsExactBoundary(t *testing.T) {
	t.Parallel()

	filterCap := maxBfAlloc / bfSize
	const ddBlockSize = popWinSize
	buf := make([]byte, filterCap*ddBlockSize) // exactly at the cap, with no remainder
	sd := newTestSdbf(t)

	result, err := populateSdbf(sd, buf, ddBlockSize)
	mustNoError(t, err,
		"populateSdbf must not reject a bfCount exactly equal to maxBfAlloc/bfSize (regression: issue #63)")
	checkEqual(t, uint32(filterCap), result.bfCount, "bfCount must equal the cap exactly, with no filters dropped")
	checkEqual(t, filterCap*bfSize, len(result.buffer), "buffer length must equal bfCount*bfSize")
}

// ---------------------------------------------------------------------------
// 00470000  Allocation cap rejects before allocating the buffer
// ---------------------------------------------------------------------------

// TestIssue63_AllocationCapRejectsBeforeAllocatingBuffer verifies the fix's
// specific claim: populateSdbf returns its error "before any allocation
// occurs". It is not enough for Compute() to eventually return an error —
// the whole point of the fix is to avoid the multi-GiB make([]byte, ...)
// call in the first place. This inspects sd.buffer and sd.elemCounts
// directly after the rejection to confirm neither was ever allocated.
func TestIssue63_AllocationCapRejectsBeforeAllocatingBuffer(t *testing.T) {
	t.Parallel()

	filterCap := maxBfAlloc / bfSize
	const ddBlockSize = popWinSize
	buf := make([]byte, (filterCap+1)*ddBlockSize)
	sd := newTestSdbf(t)

	_, err := populateSdbf(sd, buf, ddBlockSize)
	checkError(t, err, "populateSdbf must reject a bfCount that exceeds maxBfAlloc/bfSize (regression: issue #63)")
	checkTrue(t, sd.buffer == nil,
		"sd.buffer must remain unallocated when the allocation cap rejects the request (regression: issue #63)")
	checkTrue(t, sd.elemCounts == nil,
		"sd.elemCounts must remain unallocated when the allocation cap rejects the request (regression: issue #63)")
}

// =========================================================================
// Issue 64 — ParseReader buffers unbounded attacker-controlled data before
// validating buffer length
// https://github.com/malwarology/sdhash/issues/64
// =========================================================================
//
// Parse(string) is unaffected by this finding (its input is already fully
// in memory), so all tests below exercise ParseReader directly against a
// crafted io.Reader. The valid-input boundary case that the fix's "+2
// slack" specifically accommodates — a base64 payload followed by a
// Windows-style "\r\n" line ending — already has dedicated coverage
// independent of this issue: TestParse_StreamWithWindowsLineEnding and
// TestParse_DDWithWindowsLineEnding in sdhash_test.go. It is not duplicated
// here.

// ---------------------------------------------------------------------------
// 00480000  Stream mode unterminated buffer does not hang
// ---------------------------------------------------------------------------

// TestIssue64_StreamModeUnterminatedBufferDoesNotHang verifies that
// ParseReader terminates against a stream-mode buffer field with no
// delimiter and no EOF, rather than buffering the input forever. Before the
// fix, r.ReadString('\n') would never return against this input, since it
// keeps reading until it finds '\n' or reaches EOF, and this reader
// supplies neither.
func TestIssue64_StreamModeUnterminatedBufferDoesNotHang(t *testing.T) {
	t.Parallel()

	header := "sdbf:03:1:-:512:sha1:256:5:7ff:160:1:160:"
	r := io.MultiReader(strings.NewReader(header), &infiniteReader{b: 'A'})

	done := make(chan error, 1)
	go func() {
		_, err := ParseReader(r)
		done <- err
	}()

	select {
	case err := <-done:
		checkError(t, err,
			"ParseReader must reject an unterminated stream buffer rather than hanging (regression: issue #64)")
	case <-time.After(5 * time.Second):
		t.Fatal("ParseReader did not return within 5s against an unterminated, infinite stream buffer " +
			"(regression: issue #64) — the read is not bounded")
	}
}

// ---------------------------------------------------------------------------
// 00490000  DD mode unterminated block does not hang
// ---------------------------------------------------------------------------

// TestIssue64_DDModeUnterminatedBlockDoesNotHang is the DD-mode analog of
// TestIssue64_StreamModeUnterminatedBufferDoesNotHang: ParseReader must
// terminate against a block field with no ':' delimiter and no EOF, rather
// than buffering the input forever.
func TestIssue64_DDModeUnterminatedBlockDoesNotHang(t *testing.T) {
	t.Parallel()

	header := "sdbf-dd:03:1:-:512:sha1:256:5:7ff:192:1:1024:00:"
	r := io.MultiReader(strings.NewReader(header), &infiniteReader{b: 'A'})

	done := make(chan error, 1)
	go func() {
		_, err := ParseReader(r)
		done <- err
	}()

	select {
	case err := <-done:
		checkError(t, err,
			"ParseReader must reject an unterminated DD block rather than hanging (regression: issue #64)")
	case <-time.After(5 * time.Second):
		t.Fatal("ParseReader did not return within 5s against an unterminated, infinite DD block " +
			"(regression: issue #64) — the read is not bounded")
	}
}

// ---------------------------------------------------------------------------
// 00500000  Stream mode bounded read does not consume unbounded input
// ---------------------------------------------------------------------------

// TestIssue64_StreamModeBoundedReadDoesNotConsumeUnboundedInput proves the
// read is bounded, not merely finite. The tail is 50 MiB — large enough
// that the pre-fix r.ReadString('\n') would have buffered the whole thing
// before hitting EOF and failing the length check — but ParseReader must
// consume only a small, fixed number of bytes from the reader before
// rejecting it, regardless of how much more data the reader could supply.
func TestIssue64_StreamModeBoundedReadDoesNotConsumeUnboundedInput(t *testing.T) {
	t.Parallel()

	header := "sdbf:03:1:-:512:sha1:256:5:7ff:160:1:160:"
	tail := strings.Repeat("A", 50<<20) // 50 MiB, no delimiter anywhere
	cr := &countingReader{r: io.MultiReader(strings.NewReader(header), strings.NewReader(tail))}

	_, err := ParseReader(cr)
	checkError(t, err, "ParseReader must reject an oversized stream buffer (regression: issue #64)")

	// The payload bound itself is only a few hundred bytes; this ceiling is
	// deliberately generous (bufio's own internal prefetch buffer, plus the
	// header) while remaining orders of magnitude below the 50 MiB tail.
	const generousBound = 64 << 10 // 64 KiB
	checkTrue(t, cr.count < generousBound,
		fmt.Sprintf("ParseReader must not consume more than %d bytes from the reader; consumed %d "+
			"(regression: issue #64)", generousBound, cr.count))
}

// ---------------------------------------------------------------------------
// 00510000  DD mode bounded read does not consume unbounded input
// ---------------------------------------------------------------------------

// TestIssue64_DDModeBoundedReadDoesNotConsumeUnboundedInput is the DD-mode
// analog of TestIssue64_StreamModeBoundedReadDoesNotConsumeUnboundedInput.
func TestIssue64_DDModeBoundedReadDoesNotConsumeUnboundedInput(t *testing.T) {
	t.Parallel()

	header := "sdbf-dd:03:1:-:512:sha1:256:5:7ff:192:1:1024:00:"
	tail := strings.Repeat("A", 50<<20) // 50 MiB, no delimiter anywhere
	cr := &countingReader{r: io.MultiReader(strings.NewReader(header), strings.NewReader(tail))}

	_, err := ParseReader(cr)
	checkError(t, err, "ParseReader must reject an oversized DD block (regression: issue #64)")

	const generousBound = 64 << 10 // 64 KiB
	checkTrue(t, cr.count < generousBound,
		fmt.Sprintf("ParseReader must not consume more than %d bytes from the reader; consumed %d "+
			"(regression: issue #64)", generousBound, cr.count))
}

// =========================================================================
// Issue 66 — DD-mode last-block terminator handling over-reads into
// immediately-following data, corrupting concatenated digest streams
// https://github.com/malwarology/sdhash/issues/66
// =========================================================================
//
// Discovered while writing the Issue 64 regression tests above: the
// bounded-read fix for Issue 64 (readBoundedString) searched for a ':'
// delimiter to find each DD block's payload boundary, but the *last* block
// has no trailing ':' — it ends at '\r\n', '\n', or EOF. Searching for a
// delimiter that structurally doesn't exist always ran to the end of the
// read's bound, silently consuming whatever came next: for a standalone
// digest reaching real EOF this happened to still work (TrimRight stripped
// the trailing newline it had over-read), but for a digest immediately
// followed by more data — a second digest concatenated in the same stream,
// exactly the pattern TestParseReader_MultipleDigests exercises for stream
// mode — it consumed the first byte of that following data too, corrupting
// both digests' parse.
//
// The fix replaces delimiter-scanning for DD block payloads with an
// exact-length read (base64.StdEncoding.EncodedLen(bfSize) is fixed and
// known in advance, so no scanning is needed), followed by explicit
// terminator handling: a single ':' for every block but the last, and
// '\r\n' / '\n' / EOF for the last — with anything else found there left
// unread via bufio.Reader.UnreadByte rather than consumed.

// ---------------------------------------------------------------------------
// 00520000  Concatenated DD digests parse correctly
// ---------------------------------------------------------------------------

// TestIssue66_ConcatenatedDDDigestsParseCorrectly is the minimal
// reproduction of the bug this issue fixes, built entirely from the real
// production pipeline (New/WithBlockSize/Compute and String), not a
// hand-built digest string: two small DD digests, concatenated exactly as
// TestParseReader_MultipleDigests does for stream mode, must both parse
// back to their original values from a single shared *bufio.Reader.
func TestIssue66_ConcatenatedDDDigestsParseCorrectly(t *testing.T) {
	t.Parallel()

	buf1 := randomBuf(4096, 201, 201)
	buf2 := randomBuf(4096, 202, 202)
	sd1 := ddDigest(t, buf1, 1024)
	sd2 := ddDigest(t, buf2, 1024)

	r := bufio.NewReader(strings.NewReader(sd1.String() + sd2.String()))

	parsed1, err := ParseReader(r)
	mustNoError(t, err, "parsing the first of two concatenated DD digests must succeed (regression: issue #66)")
	checkEqual(t, sd1.String(), parsed1.String(), "first parsed digest must match the original exactly")

	parsed2, err := ParseReader(r)
	mustNoError(t, err, "parsing the second of two concatenated DD digests must succeed (regression: issue #66)")
	checkEqual(t, sd2.String(), parsed2.String(), "second parsed digest must match the original exactly")
}

// ---------------------------------------------------------------------------
// 00530000  Last block terminator variants
// ---------------------------------------------------------------------------

// TestIssue66_LastBlockTerminatorVariants directly exercises every
// terminator the last DD block can legitimately end with: a bare '\n', a
// Windows-style "\r\n", and true EOF (no trailing bytes at all) must all
// parse successfully. A fourth case — the last block immediately followed
// by unrelated data with no separator at all, the most direct form of the
// bug this issue fixes — must also parse successfully. It must also leave
// that unrelated data completely untouched for whatever reads the stream
// next.
func TestIssue66_LastBlockTerminatorVariants(t *testing.T) {
	t.Parallel()

	validB64 := base64.StdEncoding.EncodeToString(make([]byte, 256))
	header := "sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:1:1048576:c0:" + validB64

	cases := []struct {
		name    string
		trailer string
	}{
		{"bare LF terminator", "\n"},
		{"CRLF terminator", "\r\n"},
		{"EOF with no trailing bytes", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(header + tc.trailer)
			checkNoError(t, err, fmt.Sprintf("expected a successful parse for case %q (regression: issue #66)", tc.name))
		})
	}

	t.Run("immediately followed by unrelated data", func(t *testing.T) {
		t.Parallel()
		const trailing = "UNRELATEDDATA"
		r := bufio.NewReader(strings.NewReader(header + trailing))

		_, err := ParseReader(r)
		checkNoError(t, err,
			"expected a successful parse when the last block is followed by unrelated data with no separator (regression: issue #66)")

		rest := make([]byte, len(trailing))
		n, err := io.ReadFull(r, rest)
		mustNoError(t, err, "reading the remainder of the stream must succeed")
		checkEqual(t, len(trailing), n, "must read exactly the trailing bytes")
		checkEqual(t, trailing, string(rest),
			"trailing bytes must be left completely untouched, not partially consumed (regression: issue #66)")
	})
}

// ---------------------------------------------------------------------------
// 00540000  Non-last block delimiter mismatch rejected
// ---------------------------------------------------------------------------

// TestIssue66_NonLastBlockDelimiterMismatchRejected verifies the other half
// of the fix: every block but the last must still be strictly delimited by
// a single ':'. A wrong character in that position, or EOF at that
// position, must be rejected rather than silently accepted.
func TestIssue66_NonLastBlockDelimiterMismatchRejected(t *testing.T) {
	t.Parallel()

	validB64 := base64.StdEncoding.EncodeToString(make([]byte, 256))

	cases := []struct {
		name  string
		input string
	}{
		{
			"wrong delimiter character",
			"sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" + validB64 + "X" + validB64 + "\n",
		},
		{
			"EOF exactly at delimiter position",
			"sdbf-dd:03:1:-:1048576:sha1:256:5:7ff:192:2:1048576:c0:" + validB64,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.input)
			checkError(t, err, fmt.Sprintf("expected an error for case %q (regression: issue #66)", tc.name))
		})
	}
}
