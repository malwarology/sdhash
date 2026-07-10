# sdhash

A Go library implementing the [sdhash](https://github.com/sdhash/sdhash) similarity digest algorithm. sdhash produces compact bloom-filter-based fingerprints of binary data that can be compared to produce a similarity score in the range [0, 100]. A score of 100 means the inputs are identical; a score of 0 means they share no detectable similarity.

This library is a focused implementation of the core digest algorithm. It has no CLI, no index, and no filesystem dependencies. It takes bytes in and returns digest strings out.

This work is based on the original Go implementation by [Emiliano Ciavatta](https://github.com/eciavatta/sdhash), which in turn is based on the C++ reference implementation by [Vassil Roussev](https://github.com/hexavore) and [Candice Quates](https://github.com/candicenonsense).

## Installation

```bash
go get github.com/malwarology/sdhash
```

## Usage

### Computing a digest

```go
data, err := os.ReadFile("sample.bin")
if err != nil {
    log.Fatal(err)
}

factory, err := sdhash.New(data)
if err != nil {
    log.Fatal(err)
}

digest, err := factory.Compute()
if err != nil {
    log.Fatal(err)
}

fmt.Println(digest.String())
```

### Computing a DD (block-aligned) digest

```go
factory, err := sdhash.New(data)
if err != nil {
    log.Fatal(err)
}

digest, err := factory.WithBlockSize(65536).Compute()  // 64 KiB blocks — see Modes section for guidance
if err != nil {
    log.Fatal(err)
}
```

### Comparing two digests

```go
score, ok := digest1.Similarity(digest2)
if !ok {
    fmt.Println("comparison could not be performed")
    return
}
fmt.Printf("similarity: %d/100\n", score)
```

### Parsing a digest string

```go
digest, err := sdhash.Parse(line)
if err != nil {
    log.Fatal(err)
}
```

### Parsing digests from a file

```go
f, err := os.Open("digests.sdbf")
if err != nil {
    log.Fatal(err)
}
defer f.Close()

r := bufio.NewReader(f)
for {
    digest, err := sdhash.ParseReader(r)
    if err != nil {
        break
    }
    fmt.Println(digest.FilterSize())
}
```

### High-throughput processing

The recommended pattern for processing many inputs concurrently is one goroutine per input. Each `Compute` call produces a fully independent `Digest` with no shared state.

```go
var wg sync.WaitGroup
results := make([]sdhash.Digest, len(inputs))

for i, data := range inputs {
    wg.Add(1)
    go func(idx int, buf []byte) {
        defer wg.Done()
        factory, err := sdhash.New(buf)
        if err != nil {
            return
        }
        results[idx], _ = factory.Compute()
    }(i, data)
}
wg.Wait()
```

## Public API

```go
// New returns a factory that will produce a digest from the
// given byte slice. The slice must be at least MinFileSize (512) bytes.
func New([]byte) (Factory, error)

// Factory builds a digest. Methods return a new factory rather than
// modifying the receiver, making the type safe to share across goroutines.
type Factory interface {
    WithBlockSize(uint32) Factory  // 0 = stream mode (default)
    Compute() (Digest, error)
}

// Parse decodes a digest from a wire-format string.
func Parse(string) (Digest, error)

// ParseReader decodes a single digest from a reader.
func ParseReader(io.Reader) (Digest, error)

// Digest is a computed similarity digest.
type Digest interface {
    Similarity(Digest) (int, bool)            // similarity score in [0, 100]; false if not comparable
    String() string                      // wire-format encoding
    FilterSize() uint64                  // total bloom filter data size in bytes
    InputSize() uint64                   // size of the original input
    FilterCount() uint32                 // number of bloom filters
    FeatureDensity() float64             // total features / input size
}

// MinFileSize is the minimum input size required to compute a digest.
const MinFileSize = 512
```

## Wire format

Digests are encoded as self-describing strings. The format is compatible with the C++ reference implementation.

**Stream mode:**
```
sdbf:03:1:-:<filesize>:sha1:<bfsize>:5:7ff:<maxelem>:<bfcount>:<lastcount>:<base64data>\n
```

**DD mode:**
```
sdbf-dd:03:1:-:<filesize>:sha1:<bfsize>:5:7ff:<maxelem>:<bfcount>:<ddblocksize>(:<elemcount>:<base64data>)+\n
```

The name field is hardcoded to `-` with a length of `1`. This library treats digests as pure functions of content: the same bytes always produce the same digest string, regardless of where the data came from or what it was called.

## Modes

**Stream mode** (default) treats the input as a single stream and produces a single digest representing the file as a whole. Two stream digests score high when the files share broadly similar content across their full length. For inputs larger than 32 MiB, rank and score computation is parallelized across 32 MiB chunks before a sequential bloom filter insertion pass. The insertion pass is sequential to preserve the cross-chunk deduplication behavior that is part of the algorithm.

**DD mode** (`WithBlockSize`) divides the input into fixed-size blocks and produces one bloom filter per block. Two DD digests score high when the files share similar content within corresponding blocks. This enables localized similarity detection: you can identify which regions of two files are similar even when the files differ overall. Each block is processed independently and in parallel. A remainder block is included if it is at least `MinFileSize` bytes.

### Choosing a block size for DD mode

The block size controls the granularity of similarity detection. The rule is: **the block size should be smaller than the smallest shared region you want to detect.** A shared region smaller than one block may fall across a boundary and be missed.

**Hard constraints:**
- Minimum: `MinFileSize` (512 bytes). Blocks smaller than this are skipped.
- Maximum: no hard limit, but a block size larger than the input produces only one filter, which is equivalent to stream mode.
- Must be a meaningful fraction of the input size — if the block size is close to the input size, you get very few filters and comparison becomes unreliable.

## Known limitations and degenerate digests

sdhash extracts features by computing entropy over a sliding window and hashing high-scoring positions. When the input is repetitive or low-entropy — zero-padded PE files, sparse disk images, configuration files with repeated keys — almost everything is rejected by the entropy filter or deduplicated, and very few elements are inserted into the bloom filters. This produces a degenerate digest that does not contain enough information for a meaningful similarity comparison.

There are two observable failure modes, both confirmed by the original author of the C++ reference implementation ([sdhash/sdhash#5](https://github.com/sdhash/sdhash/issues/5#issuecomment-188952100)):

**False positive.** Two files that share no meaningful content produce a high similarity score. This happens when both digests are nearly empty — two sparse bloom filters match on their shared zeroes, and the scoring math produces a misleadingly high result. The upstream report with example malware samples is at [sdhash/sdhash#17](https://github.com/sdhash/sdhash/issues/17).

**False negative.** A file compared against an exact copy of itself produces a score of 0. This happens when the single bloom filter produced by the digest falls below the internal sparse-filter threshold (16 elements) and is excluded from scoring entirely.

Both are the same underlying problem observed from opposite directions: the digest does not contain enough features to support a valid comparison.

### Detecting degenerate digests with FeatureDensity

`FeatureDensity()` returns the ratio of total unique features inserted across all bloom filters to the original input size. It is the direct measure of how much information the digest captured. A normal high-entropy binary produces consistent density; a zero-padded or repetitive file produces density close to zero.

```go
digest, _ := factory.Compute()

density := digest.FeatureDensity()
if density < threshold {
    log.Printf("warning: feature density %.4f is below threshold; digest may be unreliable", density)
}
```

The library exposes the metric but does not enforce a threshold. The correct threshold depends on the corpus.

## C++ reference compatibility

This implementation has been cross-validated against the C++ sdhash
reference implementation across 2,860,832 pair comparisons — every
ordered pair of the 1,196-file mixedbag corpus, in both stream and DD
modes — with zero unexplained divergences.

The modern path improves on the C++ reference in three ways — two in
scoring (via `Similarity`) and one in construction (via `New`):

1. **Full popcount.** The C++ implementation uses a staged early-exit
   heuristic (`bf_bitcount_cut_256` with `slack=48`) that can reject
   filter pairs before computing their full AND-popcount. This was a
   performance optimization for the lookup-table-based popcount used in
   the original code. On modern hardware with native POPCNT instructions,
   the full computation is both faster (no branch mispredictions, no
   redundant second pass) and more accurate.

2. **Clean accumulation.** The C++ implementation initializes `score_sum`
   to -1 and uses conditional assignment on the first iteration, which
   causes a non-negative result to reset any previously accumulated
   negative. `Similarity` uses straightforward addition, which is simpler
   and does not mask degenerate filter results.

3. **Single-count feature selection.** The C++ sliding-window selector
   double-counts positions on runs of equal ranks: a position can be
   incremented by both the fast-forward block and the rescan tail of
   overlapping windows, a distribution no correct per-window minimum
   produces (issue #57). `New` selects one position per window — the
   minimum nonzero rank, rightmost of the first consecutive run — and
   increments it exactly once. Because this changes digest output, its
   effect appears in scores: over the 1,196-file mixedbag corpus, scoring
   disagrees with the C++ reference on 9.855% of pairs, of which about
   3.3% is off-by-one rounding and the substantive remainder is
   overwhelmingly small-magnitude (2–5) with a fast-descending tail, and
   no pair where the reference scored a comparison the modern path
   rejected.

## Concurrency

Every method on `Digest` is safe to call from multiple goroutines simultaneously. `Similarity`, `String`, `FilterSize`, `InputSize`, `FilterCount`, and `FeatureDensity` are read-only and may be called concurrently without restriction.

Each `New` call followed by `Compute` produces an independent `Digest` instance with no shared state. Computing many digests concurrently across different inputs is safe and is the primary pattern the library is designed for.

**`Factory` is immutable.** `WithBlockSize` returns a new factory rather than modifying the receiver. Sharing a factory across goroutines is safe, though pointless since each `Compute` call produces an independent result.

## Testing

```bash
# Run the test suite
go test -count=1 ./...

# Run with race detector (slower, use in CI)
go test -race -count=1 ./...

# Coverage report
go test -count=1 -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

The default suite achieves 100% statement coverage. It includes regression
tests for known issues verified against the C++ reference implementation.

### Deterministic corpus anchors

Two heavier tests lock digest generation and scoring against deterministic
SHA-256 anchors. Neither ships reference data — each regenerates its corpus
in-process from a fixed seed, so any drift in generation, computation, or
the captured per-row fields changes the anchor and fails the test.

```bash
# Digest-generation anchor (normal corpus, stream + DD)
go test -tags corpushash -run TestCorpusHash -timeout=0 -count=1 ./...

# Modern-scoring anchor (mixedbag corpus, all ordered pairs, stream + DD)
go test -tags corpuscompare -run TestCorpusCompare -timeout=0 -count=1 ./...
```

`corpushash` regenerates the normal corpus (66,020 files across 23
categories) and folds per-digest statistics into one anchor. `corpuscompare`
regenerates the mixedbag corpus (1,196 files), scores every ordered pair
including self-pairs with `Similarity`, and folds the per-pair
fields into one anchor per mode. Both run in CI on push to main; they are
excluded from the default suite.
