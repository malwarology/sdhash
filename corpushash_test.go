//go:build corpushash

package sdhash

// Corpushash validation test index
//
// I.  Reference corpus — stream mode
// └── 00010000  Full normal-corpus stream digest anchor
//
// II. Reference corpus — DD mode
// └── 00020000  Full normal-corpus DD digest anchor
//
// The corpushash test is the storage-free successor to the corpus test. Rather
// than shipping reference CSVs of every digest, it regenerates the normal
// corpus deterministically (bindatagenerator -n, PCG stream 0). It then computes
// the same stream and DD digest rows the sdhashtest tool emits in its corpushash
// (-l) mode. Finally, it folds those rows into a single SHA-256 anchor with the
// csvhash three-tier construction. A change to generation, digest computation,
// or the captured per-digest statistics changes the anchor and fails the test.

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Expected anchors (production scale: bdgFilesPerType files per category,
// PCG stream 0). These are the golden values computed by the reference
// pipeline (bindatagenerator -n | sdhashtest -l | csvhash) over the full
// normal corpus. Regenerate them only when an intended algorithm change is
// made, and verify against the reference tools before committing.
// ---------------------------------------------------------------------------

// Reference anchors for the full normal corpus (bindatagenerator -n defaults:
// filesPerType 3000, master seed 20260324, PCG stream 0; large overridden to
// 33-80 MiB x 20 -> 66,020 files), captured from the reference pipeline
// bindatagenerator -n | sdhashtest -l | csvhash. An empty string here means the
// anchor is unpinned: the test then computes it, prints it, and fails with an
// instruction to verify and paste the value.
const (
	corpusHashStreamAnchor = "98c9880698006cd95f7363cc3342dac23313066abbf5916f283822338cdb4462"
	corpusHashDDAnchor     = "e90b685cfbdf90077216641abbc474124e66fb2a5e438a66aa4abcc18aeb6dc4"
)

// corpusHashAnchors holds the two computed anchors.
type corpusHashAnchors struct {
	stream [32]byte
	dd     [32]byte
}

var (
	corpusHashOnce   sync.Once
	corpusHashResult *corpusHashAnchors
)

// corpusHashDigestResult is the outcome of hashing one file's stream and DD
// digest rows. Only the two 32-byte canonical-record hashes survive; the file
// bytes and digests are discarded as soon as the payloads are captured, so the
// resident set stays bounded even across the full multi-gigabyte corpus.
type corpusHashDigestResult struct {
	category string
	streamH  [32]byte
	ddH      [32]byte
	err      error
}

// buildCorpusHashAnchors plans the normal corpus and computes stream and DD
// digests for every file across a bounded worker pool. It captures each
// digest's row payload, hashes it into a canonical record, and buckets the
// records by category. It then folds those buckets into the two final anchors.
func buildCorpusHashAnchors(t *testing.T) *corpusHashAnchors {
	t.Helper()

	// Phase 1 — Sequential: consume the seed RNG to plan every file. This is
	// cheap (no bytes generated) and preserves the exact PRNG order.
	work := planNormalCorpus(bdgMinSize, bdgMaxSize, bdgFilesPerType, bdgDefaultCategories())
	t.Logf("corpushash: planned %d files", len(work))
	return computeHashAnchors(t, work)
}

// computeHashAnchors generates digests for the planned corpus, captures each
// file's stream and DD digest rows, and folds them into the two anchors. It is
// split from buildCorpusHashAnchors so the same digest-row and accumulation
// code can be exercised on a small corpus in tests.
func computeHashAnchors(t *testing.T, work []corpusWork) *corpusHashAnchors {
	t.Helper()

	// Phase 2 — Parallel: generate bytes, compute both digests, and reduce
	// each to its canonical-record hash. Each goroutine writes to its own
	// index, so no locking is required.
	results := make([]corpusHashDigestResult, len(work))

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for idx, w := range work {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, w corpusWork) {
			defer wg.Done()
			defer func() { <-sem }()

			res := corpusHashDigestResult{category: w.category}
			data := w.generate()

			streamSD, err := computeStreamDigest(data)
			if err != nil {
				res.err = fmt.Errorf("%s: stream compute: %w", w.filename, err)
				results[idx] = res
				return
			}
			ddSD, err := computeDDDigest(data)
			if err != nil {
				res.err = fmt.Errorf("%s: dd compute: %w", w.filename, err)
				results[idx] = res
				return
			}

			res.streamH = hashRecord(w.filename, streamDigestPayload(streamSD))
			res.ddH = hashRecord(w.filename, ddDigestPayload(ddSD))
			results[idx] = res
		}(idx, w)
	}

	wg.Wait()

	// Phase 3 — Sequential: bucket the record hashes by category and fold.
	streamBuckets := make(map[string][]anchorRecord)
	ddBuckets := make(map[string][]anchorRecord)

	for i, res := range results {
		if res.err != nil {
			t.Fatalf("corpushash: %v", res.err)
		}
		key := work[i].filename
		streamBuckets[res.category] = append(streamBuckets[res.category], anchorRecord{key: key, h: res.streamH})
		ddBuckets[res.category] = append(ddBuckets[res.category], anchorRecord{key: key, h: res.ddH})
	}

	return &corpusHashAnchors{
		stream: computeCorpusAnchor(streamBuckets),
		dd:     computeCorpusAnchor(ddBuckets),
	}
}

// getCorpusHashAnchors builds the anchors once, shared across the two modes.
func getCorpusHashAnchors(t *testing.T) *corpusHashAnchors {
	t.Helper()
	corpusHashOnce.Do(func() {
		corpusHashResult = buildCorpusHashAnchors(t)
	})
	return corpusHashResult
}

// =========================================================================
// I. Reference corpus — stream mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Full normal-corpus stream digest anchor
// ---------------------------------------------------------------------------

func TestCorpusHash_StreamMode(t *testing.T) {
	a := getCorpusHashAnchors(t)
	checkAnchor(t, "corpushash", "stream", corpusHashStreamAnchor, a.stream)
}

// =========================================================================
// II. Reference corpus — DD mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00020000  Full normal-corpus DD digest anchor
// ---------------------------------------------------------------------------

func TestCorpusHash_DDMode(t *testing.T) {
	a := getCorpusHashAnchors(t)
	checkAnchor(t, "corpushash", "dd", corpusHashDDAnchor, a.dd)
}
