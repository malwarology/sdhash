// Package sdhash implements the sdhash similarity digest algorithm.
//
// sdhash produces compact bloom-filter-based fingerprints of binary data
// that can be compared to produce a similarity score in the range [0, 100].
// A score of 100 means the inputs are identical; a score of 0 means they
// share no detectable similarity.
//
// This is a focused implementation of the core digest algorithm. It has no
// CLI, no index, and no filesystem dependencies. It takes bytes in and
// returns digest strings out.
//
// # Modes
//
// Stream mode (default) treats the input as a single stream and produces a
// digest representing the file as a whole. DD mode (WithBlockSize) divides
// the input into fixed-size blocks and produces one bloom filter per block,
// enabling localized similarity detection.
//
// # Usage
//
//	factory, err := sdhash.New(data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	digest, err := factory.Compute()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(digest.String())
//
//	score, ok := digest1.Compare(digest2)
//
// # Degenerate digests
//
// Low-entropy or repetitive input may produce digests without enough features
// for meaningful comparison. Use FeatureDensity to detect these cases before
// trusting a score. See the README for threshold guidance.
//
// # C++ reference compatibility
//
// CompareRef provides a scoring path that reproduces the exact behavior of
// the C++ sdhash reference implementation, including three intentional
// divergences from Compare: a staged early-exit heuristic in the
// AND-popcount calculation, conditional score accumulation semantics, and
// the single-int return convention with -1 as a degenerate sentinel.
//
// CompareRef exists for cross-validation against C++ reference output and
// for comparing digests originally produced by the C++ implementation.
// For all new work, prefer Compare which returns (score, ok).
//
// CompareRef will be removed in a future major release. See the README
// for migration guidance.
//
// # Concurrency
//
// Every method on Sdbf is safe for concurrent use. Each Compute call produces
// an independent digest with no shared state. The recommended pattern for
// high-throughput processing is one goroutine per input.
package sdhash
