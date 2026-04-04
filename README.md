# sdhash

A Go library implementing the [sdhash](https://github.com/sdhash/sdhash) similarity digest algorithm. sdhash produces compact bloom-filter-based fingerprints of binary data that can be compared to produce a similarity score in the range [0, 100]. A score of 100 means the inputs are identical; a score of 0 means they share no detectable similarity.

This library is a focused implementation of the core digest algorithm. It has no CLI, no index, and no filesystem dependencies. It takes bytes in and returns digest strings out.

This work is based on the original Go implementation by [Emiliano Ciavatta](https://github.com/eciavatta/sdhash), which in turn is based on the C++ reference implementation by [Vassil Roussev](https://github.com/hexavore) and [Candice Quates](https://github.com/candicenonsense).

## Correctness

This implementation has been verified correct against the C++ reference implementation using a 103,000-file corpus. All 103,000 files match in both stream mode and DD mode.

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

factory, err := sdhash.CreateSdbfFromBytes(data)
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
factory, err := sdhash.CreateSdbfFromBytes(data)
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
score, ok := digest1.Compare(digest2)
if !ok {
    fmt.Println("comparison could not be performed")
    return
}
fmt.Printf("similarity: %d/100\n", score)
```

### Parsing a digest string

```go
digest, err := sdhash.ParseSdbfFromString(line)
if err != nil {
    log.Fatal(err)
}
```

### High-throughput processing

The recommended pattern for processing many inputs concurrently is one goroutine per input. Each `Compute` call produces a fully independent `Sdbf` with no shared state.

```go
var wg sync.WaitGroup
results := make([]sdhash.Sdbf, len(inputs))

for i, data := range inputs {
    wg.Add(1)
    go func(idx int, buf []byte) {
        defer wg.Done()
        factory, err := sdhash.CreateSdbfFromBytes(buf)
        if err != nil {
            return
        }
        results[idx], _ = factory.Compute()
    }(i, data)
}
wg.Wait()
```

Empirically, using 3-4x the core count as the worker count is optimal because I/O wait time keeps additional workers busy during reads.

## Public API

```go
// CreateSdbfFromBytes returns a factory that will produce a digest from the
// given byte slice. The slice must be at least MinFileSize (512) bytes.
func CreateSdbfFromBytes([]byte) (SdbfFactory, error)

// SdbfFactory builds a digest. Methods return a new factory rather than
// modifying the receiver, making the type safe to share across goroutines.
type SdbfFactory interface {
    WithBlockSize(uint32) SdbfFactory  // 0 = stream mode (default)
    Compute() (Sdbf, error)
}

// ParseSdbfFromString decodes a digest from a wire-format string.
func ParseSdbfFromString(string) (Sdbf, error)

// Sdbf is a computed similarity digest.
type Sdbf interface {
    Compare(Sdbf) (int, bool)            // similarity score in [0, 100]; false if not comparable
    String() string                      // wire-format encoding
    Size() uint64                        // total bloom filter data size in bytes
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

**Practical ranges for PE malware analysis:**

| Block size | Use case |
|---|---|
| 4096 – 16384 | Shared functions or small code regions |
| 65536 – 262144 | Shared sections, overlays, or packed regions |
| 1048576+ | High-level structural similarity across large files |

A block size of 65536 (64 KiB) is a reasonable starting point for general PE analysis. Smaller values give finer detection but produce more filters, larger digests, and slower comparisons. Larger values are coarser but faster.

If you are building a UI with a slider, powers of two in the range 4096 to 1048576 cover all practical use cases. Presenting the values on a logarithmic scale reflects how the tradeoff actually behaves: the difference between 4096 and 8192 is much more significant than the difference between 524288 and 1048576.

Note that stream mode and DD mode answer different questions and are best used together. Stream mode tells you whether two files are broadly similar. DD mode tells you where they are similar. A pair that scores low in stream mode but has specific blocks scoring high in DD mode is a strong signal of code reuse in a specific region.

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

The library exposes the metric but does not enforce a threshold. The correct threshold depends on the corpus. Rough guidance for PE malware analysis:

| Density | Interpretation |
|---|---|
| > 0.10 | Normal. The digest has enough features for reliable comparison. |
| 0.02 – 0.10 | Marginal. The digest may be usable but scores should be treated with lower confidence. |
| < 0.02 | Degenerate. The digest almost certainly does not contain enough information. Scores from this digest — including self-comparison — are unreliable. |

These ranges were calibrated against the false-positive pair reported in [sdhash/sdhash#17](https://github.com/sdhash/sdhash/issues/17), where two unrelated zero-padded PE files produced stream densities of 0.008 and 0.012 and a similarity score of 100. Both fall below 0.02. Other input types (documents, disk images, shellcode) may have different natural density distributions. The recommended approach is to compute `FeatureDensity()` across a representative sample of your corpus, plot the distribution, and set the threshold at the natural gap between legitimate low-density files and degenerate ones.

Note that feature density is a function of distinct features, not file size alone. Repeating a file ten times adds almost no new features because the repeated content produces identical hashes that are rejected by the deduplication filter. Reversing the content and appending it adds features because the reversed bytes are entropically distinct. Size is a proxy for density but not a reliable one.

### When to use a cryptographic hash instead

sdhash answers the question "how similar are these two inputs?" It does not answer the question "are these two inputs identical?" The original author acknowledged this directly:

> sdhash works with the similarity digest of the data, which does not contain something like a crypto hash to establish identity.

If your workflow needs to establish identity — confirming that two files are exactly the same, detecting exact duplicates, or verifying that a file has not been modified — use a cryptographic hash (SHA-256, BLAKE2b, etc.) rather than sdhash. A crypto hash is both faster and correct for this purpose.

The recommended pattern when both identity and similarity are needed:

```go
// First: exact match via crypto hash (fast, always correct).
h1 := sha256.Sum256(data1)
h2 := sha256.Sum256(data2)
if h1 == h2 {
    fmt.Println("identical")
    return
}

// Second: similarity via sdhash (only if not identical).
d1, _ := factory1.Compute()
d2, _ := factory2.Compute()

// Third: check feature density before trusting the score.
if d1.FeatureDensity() < 0.02 || d2.FeatureDensity() < 0.02 {
    fmt.Println("one or both digests are degenerate; similarity score is unreliable")
    return
}

score, ok := d1.Compare(d2)
if !ok {
    fmt.Println("comparison could not be performed")
    return
}
fmt.Printf("similarity: %d/100\n", score)
```

This three-step pattern — crypto hash for identity, sdhash for similarity, density check for validity — covers the full range of inputs reliably, including the low-entropy and small-file cases where sdhash alone can produce misleading results.

## Concurrency

Every method on `Sdbf` is safe to call from multiple goroutines simultaneously. `Compare`, `String`, `Size`, `InputSize`, `FilterCount`, and `FeatureDensity` are read-only and may be called concurrently without restriction.

Each `CreateSdbfFromBytes` call followed by `Compute` produces an independent `Sdbf` instance with no shared state. Computing many digests concurrently across different inputs is safe and is the primary pattern the library is designed for.

**`SdbfFactory` is immutable.** `WithBlockSize` returns a new factory rather than modifying the receiver. Sharing a factory across goroutines is safe, though pointless since each `Compute` call produces an independent result.

**The inner scoring loop is the computational bottleneck.** `generateChunkScores` accounts for 50–62% of total CPU time, and instruction-level profiling confirms this is irreducible algorithmic work (rank comparisons and loop control), not overhead that can be optimized away. When processing many inputs concurrently the cores stay saturated on scoring work. Further within-input parallelism of the scoring loop was evaluated and showed no gain when a multi-worker pool is already running at the input level.

## Testing

```bash
# Run the test suite
go test -count=1 ./...

# Run with race detector (slower, use in CI)
go test -race -count=1 ./...

# Coverage report
go test -count=1 -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

The test suite achieves 100% statement coverage. It includes regression tests for known issues verified against the C++ reference implementation output.
