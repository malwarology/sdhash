package sdhash

import "testing"

// End-to-end benchmarks for the library's processing pipeline, exercised
// through the public API on small, in-memory inputs. They are a developer
// instrument: capture a baseline, make a change, capture again, and compare
// with benchstat.
//
//	go test -run '^$' -bench . -benchmem -count=10 > before.txt
//	# make a change
//	go test -run '^$' -bench . -benchmem -count=10 > after.txt
//	benchstat before.txt after.txt
//
// The stages are Compute (hashing), String (serialization), Parse
// (deserialization), and Similarity (scoring).

const (
	benchSmall = 4 * 1024
	benchMid   = 256 * 1024
	benchBlock = 64 * 1024
)

// mustDigest computes a digest for benchmark setup, failing the benchmark on
// error. blockSize == 0 selects stream mode; a nonzero value selects DD mode.
func mustDigest(b *testing.B, data []byte, blockSize uint32) Digest {
	b.Helper()
	factory, err := New(data)
	if err != nil {
		b.Fatal(err)
	}
	if blockSize > 0 {
		factory = factory.WithBlockSize(blockSize)
	}
	sd, err := factory.Compute()
	if err != nil {
		b.Fatal(err)
	}
	return sd
}

// runCompute benchmarks the full hashing pipeline (New + Compute) end to end,
// including the defensive input copy New performs.
func runCompute(b *testing.B, data []byte, blockSize uint32) {
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		factory, err := New(data)
		if err != nil {
			b.Fatal(err)
		}
		if blockSize > 0 {
			factory = factory.WithBlockSize(blockSize)
		}
		if _, err := factory.Compute(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompute measures digest construction — the dominant stage — for
// stream and DD modes across a small (fixed-cost) and a mid (algorithm-bound)
// input size.
func BenchmarkCompute(b *testing.B) {
	small := randomBuf(benchSmall, 1, 1)
	mid := randomBuf(benchMid, 2, 2)

	b.Run("stream/4KiB", func(b *testing.B) { runCompute(b, small, 0) })
	b.Run("stream/256KiB", func(b *testing.B) { runCompute(b, mid, 0) })
	b.Run("dd/256KiB", func(b *testing.B) { runCompute(b, mid, benchBlock) })
}

// BenchmarkString measures serialization of a digest to the wire format.
func BenchmarkString(b *testing.B) {
	sd := mustDigest(b, randomBuf(benchMid, 3, 3), 0)
	b.ReportAllocs()
	for b.Loop() {
		_ = sd.String()
	}
}

// BenchmarkParse measures deserialization of a digest from the wire format.
func BenchmarkParse(b *testing.B) {
	s := mustDigest(b, randomBuf(benchMid, 4, 4), 0).String()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompare measures a single pairwise similarity score for stream and
// DD digests.
func BenchmarkCompare(b *testing.B) {
	sa := mustDigest(b, randomBuf(benchMid, 5, 5), 0)
	sb := mustDigest(b, randomBuf(benchMid, 6, 6), 0)
	da := mustDigest(b, randomBuf(benchMid, 5, 5), benchBlock)
	db := mustDigest(b, randomBuf(benchMid, 6, 6), benchBlock)

	b.Run("stream", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sa.Similarity(sb)
		}
	})
	b.Run("dd", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			da.Similarity(db)
		}
	})
}
