//go:build compat

package sdhash

// Compat validation test index
//
// I. C++ reference-compatible scoring — stream mode
// └── 00010000  Full compat corpus stream score validation
//
// II. C++ reference-compatible scoring — DD mode
// └── 00020000  Full compat corpus DD score validation

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Compat corpus constants
// ---------------------------------------------------------------------------

const (
	compatDefaultMinSize = 4097
	compatDefaultMaxSize = 10_485_760
	compatPerCat         = 75 // 1200 / 16
)

// ---------------------------------------------------------------------------
// compatCategory describes a type of generated test file for the compat corpus.
// ---------------------------------------------------------------------------

type compatCategory struct {
	name    string
	gen     func(rng *rand.Rand, size int) []byte
	minSize int // 0 means use compatDefaultMinSize
	maxSize int // 0 means use compatDefaultMaxSize
}

// compatCategories returns the ordered category list matching
// defaultCategoryConfigs in bindatagenerator. Order and size overrides must
// be exact — they determine the seed chain consumed during mixedbag generation.
func compatCategories() []compatCategory {
	return []compatCategory{
		{"random", genRandom, 0, 0},
		{"sparse", genSparse, 0, 0},
		{"repetitive", genRepetitive, 0, 0},
		{"structured", genStructured, 0, 0},
		{"low_entropy", genLowEntropy, 0, 0},
		{"subfloor_entropy", genSubfloorEntropy, 0, 0},
		{"document_like", genDocumentLike, 0, 0},
		{"ole2_vba_dropper", genOLE2VBADropper, 4608, 51200},
		{"large", genLarge, 33 * 1024 * 1024, 80 * 1024 * 1024},
		{"powershell_pure", genPowerShellPure, 0, 0},
		{"powershell_embedded_b64", genPowerShellEmbeddedB64, 0, 0},
		{"powershell_embedded_hex", genPowerShellEmbeddedHex, 0, 0},
		{"powershell_signed", genPowerShellSigned, 0, 0},
		{"javascript_pure", genJavaScriptPure, 0, 0},
		{"javascript_embedded_b64", genJavaScriptEmbeddedB64, 0, 0},
		{"javascript_embedded_hex", genJavaScriptEmbeddedHex, 0, 0},
	}
}

// ---------------------------------------------------------------------------
// compatDigests holds both stream and DD digests keyed by bare filename.
// ---------------------------------------------------------------------------

type compatDigests struct {
	stream map[string]Sdbf
	dd     map[string]Sdbf
}

// compatOnce ensures corpus generation and hashing runs only once, shared
// across TestCompat_StreamMode and TestCompat_DDMode.
var (
	compatOnce   sync.Once
	compatResult *compatDigests
)

// buildCompatDigests generates all compat corpus files and computes both a
// stream digest and a DD digest for each. Files smaller than MinFileSize are
// skipped. Generation is sequential (to preserve PRNG order); digest
// computation is parallelized over runtime.NumCPU() goroutines.
func buildCompatDigests(t *testing.T) *compatDigests {
	t.Helper()

	// Mixedbag uses PCG stream 1, independent of the normal corpus (stream 0).
	seedRng := rand.New(rand.NewPCG(uint64(corpusMasterSeed), 1))

	// ------------------------------------------------------------------
	// Phase 1 — Sequential: consume seedRng and build the work list.
	// ------------------------------------------------------------------
	type workItem struct {
		filename string
		data     []byte
	}

	var items []workItem

	for _, cat := range compatCategories() {
		lo, hi := compatDefaultMinSize, compatDefaultMaxSize
		if cat.minSize > 0 {
			lo = cat.minSize
		}
		if cat.maxSize > 0 {
			hi = cat.maxSize
		}

		sizes := generateSizes(seedRng, compatPerCat, lo, hi)
		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			filename := fmt.Sprintf("%s_%06d_%d.bin", cat.name, i, size)

			rng := rand.New(rand.NewPCG(uint64(fileSeed), 0))
			data := cat.gen(rng, size)

			if len(data) < MinFileSize {
				continue
			}

			items = append(items, workItem{filename: filename, data: data})
		}
	}

	t.Logf("compat: generated %d files above MinFileSize", len(items))

	// ------------------------------------------------------------------
	// Phase 2 — Parallel: compute stream and DD digests.
	// ------------------------------------------------------------------
	type result struct {
		filename string
		stream   Sdbf
		dd       Sdbf
		err      error
	}

	results := make([]result, len(items))

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for idx, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, item workItem) {
			defer wg.Done()
			defer func() { <-sem }()

			res := result{filename: item.filename}

			factory, err := New(item.data)
			if err != nil {
				res.err = fmt.Errorf("New(%s): %w", item.filename, err)
				results[idx] = res
				return
			}

			streamSD, err := factory.Compute()
			if err != nil {
				res.err = fmt.Errorf("stream Compute(%s): %w", item.filename, err)
				results[idx] = res
				return
			}

			ddSD, err := factory.WithBlockSize(corpusDDBlockSize).Compute()
			if err != nil {
				res.err = fmt.Errorf("dd Compute(%s): %w", item.filename, err)
				results[idx] = res
				return
			}

			res.stream = streamSD
			res.dd = ddSD
			results[idx] = res
		}(idx, item)
	}

	wg.Wait()

	// ------------------------------------------------------------------
	// Phase 3 — Collect into maps; fail fast on any compute error.
	// ------------------------------------------------------------------
	streamMap := make(map[string]Sdbf, len(results))
	ddMap := make(map[string]Sdbf, len(results))

	for _, res := range results {
		if res.err != nil {
			t.Errorf("compat: digest error: %v", res.err)
			continue
		}
		streamMap[res.filename] = res.stream
		ddMap[res.filename] = res.dd
	}

	if t.Failed() {
		t.FailNow()
	}

	return &compatDigests{stream: streamMap, dd: ddMap}
}

// getCompatDigests returns the shared digest maps, building them once.
func getCompatDigests(t *testing.T) *compatDigests {
	t.Helper()
	compatOnce.Do(func() {
		compatResult = buildCompatDigests(t)
	})
	return compatResult
}

// ---------------------------------------------------------------------------
// compatPair is one resolved row from the reference CSV, ready for scoring.
// ---------------------------------------------------------------------------

type compatPair struct {
	file1 string
	file2 string
	sd1   *sdbf
	sd2   Sdbf
	want  int
}

// compatPairResult is the scored outcome of one pair.
type compatPairResult struct {
	file1 string
	file2 string
	got   int
	want  int
}

// runCompatValidation drives the CSV comparison for one mode.
// Rows are read sequentially (csv.Reader is not goroutine-safe), then all
// CompareRef calls are fanned out across runtime.NumCPU() goroutines so the
// scoring saturates available cores rather than running on one.
func runCompatValidation(t *testing.T, mode string, digests map[string]Sdbf, csvPath string) {
	t.Helper()

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("compat %s: cannot open %s: %v", mode, csvPath, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("compat %s: close %s: %v", mode, csvPath, err)
		}
	}()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("compat %s: cannot create gzip reader for %s: %v", mode, csvPath, err)
	}
	defer func() {
		if err := gz.Close(); err != nil {
			t.Errorf("compat %s: close gzip %s: %v", mode, csvPath, err)
		}
	}()

	r := csv.NewReader(gz)
	r.FieldsPerRecord = 3

	// Skip header row.
	if _, err := r.Read(); err != nil {
		t.Fatalf("compat %s: cannot read header from %s: %v", mode, csvPath, err)
	}

	// ------------------------------------------------------------------
	// Phase 1 — Sequential: read all CSV rows and resolve digests.
	// csv.Reader is not goroutine-safe; keep this single-threaded.
	// ------------------------------------------------------------------
	var pairs []compatPair
	var parseErrors int

	for {
		rec, err := r.Read()
		if err != nil {
			break // EOF
		}

		file1, file2, wantStr := rec[0], rec[1], rec[2]

		want, err := strconv.Atoi(wantStr)
		if err != nil {
			t.Errorf("compat %s: cannot parse score %q for (%s, %s): %v", mode, wantStr, file1, file2, err)
			parseErrors++
			continue
		}

		sd1, ok1 := digests[file1]
		sd2, ok2 := digests[file2]
		if !ok1 || !ok2 {
			missing := file1
			if !ok1 && !ok2 {
				missing = file1 + " and " + file2
			} else if !ok2 {
				missing = file2
			}
			t.Errorf("compat %s: digest not found for %s", mode, missing)
			parseErrors++
			continue
		}

		internal1, ok := sd1.(*sdbf)
		if !ok {
			t.Errorf("compat %s: %s: unexpected Sdbf implementation type", mode, file1)
			parseErrors++
			continue
		}

		pairs = append(pairs, compatPair{
			file1: file1,
			file2: file2,
			sd1:   internal1,
			sd2:   sd2,
			want:  want,
		})
	}

	t.Logf("compat %s: loaded %d pairs (%d parse/lookup errors)", mode, len(pairs), parseErrors)

	// ------------------------------------------------------------------
	// Phase 2 — Parallel: score every pair.
	// CompareRef is read-only on immutable sdbf values — concurrent calls
	// are safe with no locking required.
	// A ticker goroutine reads an atomic counter incremented by each worker
	// so progress is visible while scoring is in flight.
	// ------------------------------------------------------------------
	pairResults := make([]compatPairResult, len(pairs))

	var scored atomic.Int64
	total := int64(len(pairs))
	var lastPct atomic.Int64 // last reported 10% milestone

	// Ticker goroutine: logs at each 10% milestone while workers run.
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := scored.Load()
				pct := 10 * (n * 10 / total) // rounds down to nearest 10%
				if pct > lastPct.Load() && lastPct.CompareAndSwap(pct-10, pct) {
					t.Logf("compat %s: scored %d / %d pairs (%d%%)...",
						mode, n, total, pct)
				}
			case <-done:
				return
			}
		}
	}()

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for idx, p := range pairs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p compatPair) {
			defer wg.Done()
			defer func() { <-sem }()
			pairResults[idx] = compatPairResult{
				file1: p.file1,
				file2: p.file2,
				got:   p.sd1.CompareRef(p.sd2),
				want:  p.want,
			}
			scored.Add(1)
		}(idx, p)
	}

	wg.Wait()
	close(done) // stop the ticker goroutine

	// ------------------------------------------------------------------
	// Phase 3 — Sequential: tally mismatches.
	// ------------------------------------------------------------------
	totalMismatches := 0

	for _, res := range pairResults {
		if res.got != res.want {
			t.Errorf("compat %s: (%s, %s): got %d, want %d",
				mode, res.file1, res.file2, res.got, res.want)
			totalMismatches++
		}
	}

	t.Logf("compat %s: checked %d pairs, %d mismatches", mode, len(pairResults), totalMismatches)
}

// =========================================================================
// I. C++ reference-compatible scoring — stream mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Full compat corpus stream score validation
// ---------------------------------------------------------------------------

func TestCompat_StreamMode(t *testing.T) {
	d := getCompatDigests(t)
	runCompatValidation(t, "stream", d.stream, "testdata/compat_stream.csv.gz")
}

// =========================================================================
// II. C++ reference-compatible scoring — DD mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00020000  Full compat corpus DD score validation
// ---------------------------------------------------------------------------

func TestCompat_DDMode(t *testing.T) {
	d := getCompatDigests(t)
	runCompatValidation(t, "dd", d.dd, "testdata/compat_dd.csv.gz")
}
