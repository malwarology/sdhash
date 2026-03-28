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

digest, err := factory.WithBlockSize(65536).Compute()
if err != nil {
    log.Fatal(err)
}
```

### Comparing two digests

```go
score := digest1.Compare(digest2)
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
    Compare(Sdbf) int                    // similarity score in [0, 100]
    CompareSample(Sdbf, uint32) int      // score using at most n filters
    String() string                      // wire-format encoding
    Size() uint64                        // total bloom filter data size in bytes
    InputSize() uint64                   // size of the original input
    FilterCount() uint32                 // number of bloom filters
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

**Stream mode** (default) treats the input as a single stream. For inputs larger than 32 MiB, rank and score computation is parallelized across 32 MiB chunks before a sequential bloom filter insertion pass. The insertion pass is sequential to preserve the cross-chunk deduplication behavior that is part of the algorithm.

**DD mode** (`WithBlockSize`) produces one bloom filter per aligned block, enabling block-level similarity comparisons. Each block is processed independently and in parallel. A remainder block is included if it is at least `MinFileSize` bytes.

## Concurrency

Every method on `Sdbf` is safe to call from multiple goroutines simultaneously. `Compare`, `CompareSample`, `String`, `Size`, `InputSize`, and `FilterCount` are read-only and may be called concurrently without restriction.

Each `CreateSdbfFromBytes` call followed by `Compute` produces an independent `Sdbf` instance with no shared state. Computing many digests concurrently across different inputs is safe and is the primary pattern the library is designed for.

**`SdbfFactory` is immutable.** `WithBlockSize` returns a new factory rather than modifying the receiver. Sharing a factory across goroutines is safe, though pointless since each `Compute` call produces an independent result.

**SHA1 is the computational bottleneck.** The inner loop computes SHA1 over a 64-byte sliding window at every candidate position in the input. This dominates CPU time. When processing many inputs concurrently the cores stay saturated on SHA1 work. Further within-input parallelism of the SHA1 loop was evaluated and showed no gain when a multi-worker pool is already running at the input level.

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
