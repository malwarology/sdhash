package sdhash

import (
	"os"
	"strings"
	"testing"
)

// Regression test index
//
// I. Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
//    https://github.com/eciavatta/sdhash/issues/1
// ├── 00010000  Default index not created
// ├── 00020000  Stream hash matches reference
// ├── 00030000  DD hash matches reference
// ├── 00040000  Stream and DD parsed score in range
// ├── 00050000  Round-trip stream reference
// └── 00060000  Round-trip DD reference
//
// II. Issue 2 — Feature density detection for degenerate stream mode digests
//    https://github.com/malwarology/sdhash/issues/2
// ├── 00070000  Degenerate stream digests
// └── 00080000  DD mode no false positive
//
// III. Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
//    https://github.com/malwarology/sdhash/issues/3
// └── 00090000  High block count DD mode
//
// IV. Issue 4 — Unbounded memory allocation in ParseSdbfFromString
//    https://github.com/malwarology/sdhash/issues/4
// ├── 00100000  Parse oversized bfCount
// └── 00110000  Parse zero bfSize

// =========================================================================
// I. Issue 1 — Hash Mismatch Between Reference Implementation and Go Implementation
// https://github.com/eciavatta/sdhash/issues/1
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Default index not created
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
// 00020000  Stream hash matches reference
// ---------------------------------------------------------------------------

func TestIssue1StreamHash_MatchesReference(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/issue1.bin")
	mustNoError(t, err)

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

	data, err := os.ReadFile("testdata/issue1.bin")
	mustNoError(t, err)

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
// II. Issue 2 — Feature density detection for degenerate stream mode digests
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

	dataA, err := os.ReadFile("testdata/issue2a.bin")
	mustNoError(t, err)
	dataB, err := os.ReadFile("testdata/issue2b.bin")
	mustNoError(t, err)

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

	dataA, err := os.ReadFile("testdata/issue2a.bin")
	mustNoError(t, err)
	dataB, err := os.ReadFile("testdata/issue2b.bin")
	mustNoError(t, err)

	ddA := ddDigest(t, dataA, 65536)
	ddB := ddDigest(t, dataB, 65536)

	score := ddA.Compare(ddB)
	checkEqual(t, 0, score,
		"issue2 DD comparison must be 0")
}

// =========================================================================
// III. Issue 3 — Unbounded goroutine spawning in generateBlockSdbf
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
// IV. Issue 4 — Unbounded memory allocation in ParseSdbfFromString
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
