package sdhash

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Testdata helpers
// ---------------------------------------------------------------------------

const testdataKeyHex = "73646861736874657374646174616b6579313233343536373839306162636465"

// decryptTestFile reads a .bin.enc file, decrypts it with AES-256-GCM using
// the hardcoded testdata key, and returns the plaintext. The test is stopped
// immediately via t.Fatalf on any error.
func decryptTestFile(t *testing.T, path string) []byte {
	t.Helper()

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("decryptTestFile: failed to read %s: %v", path, err)
	}

	key, err := hex.DecodeString(testdataKeyHex)
	if err != nil {
		t.Fatalf("decryptTestFile: failed to decode key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("decryptTestFile: failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("decryptTestFile: failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		t.Fatalf("decryptTestFile: %s is too short to contain a nonce", path)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decryptTestFile: failed to decrypt %s: %v", path, err)
	}

	return plaintext
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

// mustNoError stops the test immediately if err is non-nil.
func mustNoError(t *testing.T, err error, msg ...string) {
	t.Helper()
	if err != nil {
		if len(msg) > 0 {
			t.Fatalf("%s: unexpected error: %v", msg[0], err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
}

// checkNoError records a failure if err is non-nil but lets the test continue.
func checkNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", msg, err)
	}
}

// checkError records a failure if err is nil.
func checkError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected an error, got nil", msg)
	}
}

// checkEqual records a failure if got != want.
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

// checkNotNil records a failure if v is nil.
func checkNotNil(t *testing.T, v any, msg string) {
	t.Helper()
	if v == nil {
		t.Errorf("%s: expected non-nil value, got nil", msg)
	}
}

// checkTrue records a failure if condition is false.
func checkTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Errorf("%s: condition was false", msg)
	}
}

// checkGreater records a failure if got <= threshold.
func checkGreater[T interface {
	~int | ~uint32 | ~uint64 | ~float64
}](t *testing.T, got, threshold T, msg string) {
	t.Helper()
	if got <= threshold {
		t.Errorf("%s: got %v, want > %v", msg, got, threshold)
	}
}

// checkAtLeast records a failure if got < min.
func checkAtLeast[T interface {
	~int | ~uint32 | ~uint64 | ~float64
}](t *testing.T, got, min T, msg string) {
	t.Helper()
	if got < min {
		t.Errorf("%s: got %v, want >= %v", msg, got, min)
	}
}

// checkAtMost records a failure if got > max.
func checkAtMost[T interface {
	~int | ~uint32 | ~uint64 | ~float64
}](t *testing.T, got, max T, msg string) {
	t.Helper()
	if got > max {
		t.Errorf("%s: got %v, want <= %v", msg, got, max)
	}
}

// checkLen records a failure if len(s) != want.
func checkLen[T any](t *testing.T, s []T, want int, msg string) {
	t.Helper()
	if len(s) != want {
		t.Errorf("%s: got len %d, want %d", msg, len(s), want)
	}
}

// checkNotPanics records a failure if f() panics.
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
// Digest construction helpers
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
	factory, err := New(buf)
	mustNoError(t, err)
	sd, err := factory.Compute()
	mustNoError(t, err)
	return sd
}

// ddDigest computes a DD-mode digest for buf with the given block size and stops the test on error.
func ddDigest(t *testing.T, buf []byte, blockSize uint32) Sdbf {
	t.Helper()
	factory, err := New(buf)
	mustNoError(t, err)
	sd, err := factory.WithBlockSize(blockSize).Compute()
	mustNoError(t, err)
	return sd
}

// newTestSdbf builds a minimal internal sdbf ready for generateChunkSdbf.
func newTestSdbf(t *testing.T) *sdbf {
	t.Helper()
	sd := &sdbf{
		bfSize:         bfSize,
		bfCount:        1,
		bigFilters:     make([]*bloomFilter, 0, 1),
		popWinSize:     popWinSize,
		threshold:      threshold,
		blockSize:      blockSize,
		entropyWinSize: entropyWinSize,
		maxElem:        maxElem,
	}
	bf, err := newBloomFilter(bigFilter, defaultHashCount, bigFilterElem)
	mustNoError(t, err)
	sd.bigFilters = append(sd.bigFilters, bf)
	return sd
}

// ---------------------------------------------------------------------------
// generateChunkScores contract helpers (issue #57)
// ---------------------------------------------------------------------------

// chunkScoresOf runs the production generateChunkScores over ranks (with
// chunkSize == len(ranks)) and returns the resulting chunkScores.
func chunkScoresOf(ranks []uint16) []uint16 {
	sd := &sdbf{popWinSize: popWinSize}
	scores := make([]uint16, len(ranks))
	sd.generateChunkScores(ranks, uint64(len(ranks)), scores, nil)
	return scores
}

// bruteScoresFirstRun is the independent per-window specification of the fixed
// generateChunkScores selection rule: for each window, seed at the left edge,
// take the minimum nonzero rank, break ties by the rightmost element of the
// first consecutive run of that value, and increment that position exactly once
// (only if its rank is > 0). It carries no state between windows, so it cannot
// reproduce the pre-fix double-count; a correct generateChunkScores must match
// it on every input.
//
//goland:noinspection DuplicatedCode
func bruteScoresFirstRun(ranks []uint16) []uint16 {
	scores := make([]uint16, len(ranks))
	chunkSize := uint64(len(ranks))
	popWin := uint64(popWinSize)
	if chunkSize <= popWin {
		return scores
	}
	for w := uint64(0); w < chunkSize-popWin; w++ {
		minRank := ranks[w]
		minPos := w
		for j := w + 1; j < w+popWin; j++ {
			if ranks[j] < minRank && ranks[j] > 0 {
				minRank = ranks[j]
				minPos = j
			} else if minPos == j-1 && ranks[j] == minRank {
				minPos = j
			}
		}
		if ranks[minPos] > 0 {
			scores[minPos]++
		}
	}
	return scores
}

// firstDiffUint16 returns the index of the first position at which a and b
// differ, or -1 if they are equal.
func firstDiffUint16(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// rankCasesFor generates the adversarial rank inputs for a single category
// across a fixed size ladder, seeded deterministically. Categories:
// highentropy, tieheavy, zeroladen, persistmin, monotonic, allequal, allzero.
func rankCasesFor(category string, seed uint64) [][]uint16 {
	rng := rand.New(rand.NewPCG(seed, 0x9E3779B9))
	sizes := []int{popWinSize + 2, popWinSize + 10, 200, 1000, 4096}
	var out [][]uint16

	for _, n := range sizes {
		r := make([]uint16, n)
		switch category {
		case "highentropy": // mostly distinct values
			for i := range r {
				r[i] = uint16(1 + rng.IntN(1000))
			}
		case "tieheavy": // tiny value set → many runs and non-consecutive ties
			for i := range r {
				r[i] = uint16(1 + rng.IntN(3))
			}
		case "zeroladen": // ~40% zeros interspersed with small values
			for i := range r {
				if rng.IntN(10) < 4 {
					r[i] = 0
				} else {
					r[i] = uint16(1 + rng.IntN(5))
				}
			}
		case "persistmin": // low value held for long stretches
			for i := range r {
				r[i] = uint16(50 + rng.IntN(50))
			}
			for i := 0; i < n; i += popWinSize * 2 {
				runLen := 1 + rng.IntN(popWinSize)
				for k := 0; k < runLen && i+k < n; k++ {
					r[i+k] = uint16(1 + rng.IntN(2))
				}
			}
		case "monotonic": // increasing; min always at the left edge
			for i := range r {
				r[i] = uint16(1 + i%1000)
			}
		case "allequal": // every position equal and nonzero
			for i := range r {
				r[i] = 7
			}
		case "allzero": // every position zero (left as the zero value)
		default:
			panic("rankCasesFor: unknown category " + category)
		}
		out = append(out, r)
	}
	return out
}

// checkChunkScoresMatchSpec asserts that the production generateChunkScores
// output for ranks equals the per-window specification (bruteScoresFirstRun),
// reporting the first divergence with surrounding context.
func checkChunkScoresMatchSpec(t *testing.T, ranks []uint16, msg string) {
	t.Helper()
	got := chunkScoresOf(ranks)
	want := bruteScoresFirstRun(ranks)
	idx := firstDiffUint16(got, want)
	if idx < 0 {
		return
	}
	lo := idx - 3
	if lo < 0 {
		lo = 0
	}
	hi := idx + 4
	if hi > len(ranks) {
		hi = len(ranks)
	}
	t.Errorf("%s: chunkScores diverge from per-window spec at pos %d (got=%d want=%d)\n  ranks[%d:%d]=%v\n  got  [%d:%d]=%v\n  want [%d:%d]=%v",
		msg, idx, got[idx], want[idx], lo, hi, ranks[lo:hi], lo, hi, got[lo:hi], lo, hi, want[lo:hi])
}

// checkChunkScoresGolden asserts that the production generateChunkScores output
// for ranks equals the pinned expected chunkScores.
func checkChunkScoresGolden(t *testing.T, ranks, want []uint16, msg string) {
	t.Helper()
	got := chunkScoresOf(ranks)
	if idx := firstDiffUint16(got, want); idx >= 0 {
		t.Errorf("%s: chunkScores mismatch at pos %d (got=%d want=%d)\n  got:  %v\n  want: %v",
			msg, idx, got[idx], want[idx], got, want)
	}
}
