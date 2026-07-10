//go:build corpuscompare

package sdhash

// Corpuscompare validation test index
//
// I.  Reference corpus — stream mode
// └── 00010000  Full mixedbag-corpus stream pairwise-score anchor
//
// II. Reference corpus — DD mode
// └── 00020000  Full mixedbag-corpus DD pairwise-score anchor
//
// The corpuscompare test regenerates the mixedbag corpus deterministically.
// It scores every ordered pair (including self-pairs). It then folds the
// resulting rows into a single SHA-256 anchor per mode. A change to
// generation, digest computation, scoring, or the captured per-pair fields
// changes the anchor and fails the test.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Reference anchors for the full mixedbag corpus
// ---------------------------------------------------------------------------

const (
	corpusCompareStreamAnchor = "6cd9b5f8f1f018e6e4d0c5acec011df05de1176c9e61ddde116a0f7a4285cc49"
	corpusCompareDDAnchor     = "408b519b5115c4b8683fa7ff8f20c5c61c615ab69c63308976ca9be9f7c3090a"
)

// corpusCompareAnchors holds the two computed anchors.
type corpusCompareAnchors struct {
	stream [32]byte
	dd     [32]byte
}

var (
	corpusCompareOnce   sync.Once
	corpusCompareResult *corpusCompareAnchors
)

// compareDigest is one corpus file reduced to what pairwise scoring needs. It
// holds the category (half of the anchor bucket), the bare filename (half of
// the anchor key), both mode digests, and each mode's feature density. The
// density is captured once here so the N×N loop does not recompute it.
type compareDigest struct {
	category   string
	filename   string
	stream     Digest
	dd         Digest
	streamDens float64
	ddDens     float64
	streamOK   bool
	ddOK       bool
}

// buildCorpusCompareAnchors plans the mixedbag corpus and computes stream and
// DD digests for every file across a bounded worker pool. It scores every
// ordered pair (i, j) — including i == j — in both modes. Each pair's compare
// row is hashed into a canonical record and bucketed by category pair. It then
// folds those buckets into the two final anchors.
func buildCorpusCompareAnchors(t *testing.T) *corpusCompareAnchors {
	t.Helper()

	// Phase 1 — Sequential: consume the seed RNG to plan every file (cheap,
	// no bytes generated) preserving the exact PRNG order.
	work := planMixedbagCorpus(bdgMinSize, bdgMaxSize, bdgMixedBag, bdgDefaultCategories())
	t.Logf("corpuscompare: planned %d files", len(work))
	return computeCompareAnchors(t, work)
}

// computeCompareAnchors generates digests for the planned corpus, scores every
// ordered pair in both modes, and folds the rows into the two anchors. It is
// split from buildCorpusCompareAnchors so the same scoring and accumulation
// code can be exercised on a small corpus in tests.
func computeCompareAnchors(t *testing.T, work []corpusWork) *corpusCompareAnchors {
	t.Helper()

	// Phase 2 — Parallel: generate bytes and compute both digests per file.
	// Unlike corpushash the digests are retained: every file is compared
	// against every other, so all digests must be resident at once.
	digests := make([]compareDigest, len(work))

	var firstErr atomic.Value // stores error
	{
		sem := make(chan struct{}, runtime.NumCPU())
		var wg sync.WaitGroup
		for idx, w := range work {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, w corpusWork) {
				defer wg.Done()
				defer func() { <-sem }()

				data := w.generate()
				streamSD, err := computeStreamDigest(data)
				if err != nil {
					firstErr.CompareAndSwap(nil, fmt.Errorf("%s: stream compute: %w", w.filename, err))
					return
				}
				ddSD, err := computeDDDigest(data)
				if err != nil {
					firstErr.CompareAndSwap(nil, fmt.Errorf("%s: dd compute: %w", w.filename, err))
					return
				}
				digests[idx] = compareDigest{
					category:   w.category,
					filename:   w.filename,
					stream:     streamSD,
					dd:         ddSD,
					streamDens: streamSD.FeatureDensity(),
					ddDens:     ddSD.FeatureDensity(),
					streamOK:   true,
					ddOK:       true,
				}
			}(idx, w)
		}
		wg.Wait()
	}
	if e := firstErr.Load(); e != nil {
		t.Fatalf("corpuscompare: %v", e.(error))
	}
	for i := range digests {
		if !digests[i].streamOK || !digests[i].ddOK {
			t.Fatalf("corpuscompare: missing digest at index %d", i)
		}
	}

	// Phase 3 — Parallel: score every ordered pair in both modes. Each outer
	// index i owns a contiguous, disjoint output range [i*n, i*n+n), so the
	// record slices are written without locking. Scoring uses Similarity, the
	// modern public API.
	n := len(digests)
	streamRecs := make([]anchorRecord, n*n)
	ddRecs := make([]anchorRecord, n*n)

	var scored atomic.Int64
	total := int64(n) * int64(n)
	var lastPct atomic.Int64

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c := scored.Load()
				pct := 10 * (c * 10 / total)
				if pct > lastPct.Load() && lastPct.CompareAndSwap(pct-10, pct) {
					t.Logf("corpuscompare: scored %d / %d pairs (%d%%)...", c, total, pct)
				}
			case <-done:
				return
			}
		}
	}()

	{
		sem := make(chan struct{}, runtime.NumCPU())
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()

				a := digests[i]
				base := i * n
				for j := 0; j < n; j++ {
					b := digests[j]
					key := compareKey(a.filename, b.filename)

					sScore, sOk := a.stream.Similarity(b.stream)
					streamRecs[base+j] = anchorRecord{
						key: key,
						h:   hashRecord(key, comparePayload(a.streamDens, b.streamDens, sScore, sOk)),
					}

					dScore, dOk := a.dd.Similarity(b.dd)
					ddRecs[base+j] = anchorRecord{
						key: key,
						h:   hashRecord(key, comparePayload(a.ddDens, b.ddDens, dScore, dOk)),
					}
				}
				scored.Add(int64(n))
			}(i)
		}
		wg.Wait()
	}
	close(done)

	// Phase 4 — Sequential: bucket the record hashes by category pair and
	// fold. The (i, j) indices are recovered from the flat position, so the
	// bucket name need not be stored per record.
	streamBuckets := make(map[string][]anchorRecord)
	ddBuckets := make(map[string][]anchorRecord)
	for idx := 0; idx < n*n; idx++ {
		i := idx / n
		j := idx % n
		bucket := digests[i].category + "/" + digests[j].category
		streamBuckets[bucket] = append(streamBuckets[bucket], streamRecs[idx])
		ddBuckets[bucket] = append(ddBuckets[bucket], ddRecs[idx])
	}

	return &corpusCompareAnchors{
		stream: computeCorpusAnchor(streamBuckets),
		dd:     computeCorpusAnchor(ddBuckets),
	}
}

// getCorpusCompareAnchors builds the anchors once, shared across the two modes.
func getCorpusCompareAnchors(t *testing.T) *corpusCompareAnchors {
	t.Helper()
	corpusCompareOnce.Do(func() {
		corpusCompareResult = buildCorpusCompareAnchors(t)
	})
	return corpusCompareResult
}

// =========================================================================
// I. Reference corpus — stream mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Full mixedbag-corpus stream pairwise-score anchor
// ---------------------------------------------------------------------------

func TestCorpusCompare_StreamMode(t *testing.T) {
	a := getCorpusCompareAnchors(t)
	checkAnchor(t, "corpuscompare", "stream", corpusCompareStreamAnchor, a.stream)
}

// =========================================================================
// II. Reference corpus — DD mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00020000  Full mixedbag-corpus DD pairwise-score anchor
// ---------------------------------------------------------------------------

func TestCorpusCompare_DDMode(t *testing.T) {
	a := getCorpusCompareAnchors(t)
	checkAnchor(t, "corpuscompare", "dd", corpusCompareDDAnchor, a.dd)
}
