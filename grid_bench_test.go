//go:build grid

package sdhash

// Profiling grid — Layer 4: benchstat/pprof benchmark matrix.
//
// These mirror the collector cells as thin, deterministic go-test benchmarks
// for tracking a specific change: run before and after a fix, then compare with
// benchstat, or attach -cpuprofile/-memprofile to one cell. They reuse the same
// grid dataset (planGrid seeds) so numbers line up with the Layer 3
// distributions.
//
// Where the collectors explore ("collect once, slice many ways"), the
// benchmarks confirm ("did this cell get faster, significantly"). Selective by
// design — a representative slice, not the full 11 GiB grid.
//
//	go test -tags grid -run '^$' -bench BenchmarkStreamHash -benchmem
//	go test -tags grid -run '^$' -bench BenchmarkStreamHash -count 10 > new.txt
//	benchstat old.txt new.txt
//	go test -tags grid -run '^$' -bench 'BenchmarkStreamHash/4M' \
//	    -cpuprofile cpu.out
//
// Honors -grid.max (cap sizes) and -grid.type (restrict hashing to one type).

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

// benchPoolMax bounds the number of distinct files per size cell so benchmark
// setup stays affordable at the large rungs.
const benchPoolMax = 8

var benchBufCache = map[string][][]byte{}

// benchBuffers returns a deterministic, type-mixed pool of buffers for one size
// rung (or a single type when onlyType is set). Cached across benchmark
// restarts so setup cost isn't paid repeatedly.
func benchBuffers(sizeIdx, reqSize, reps int, onlyType string) [][]byte {
	key := fmt.Sprintf("%d|%s|%d", sizeIdx, onlyType, reps)
	if v, ok := benchBufCache[key]; ok {
		return v
	}
	types := gridTypes()
	var pool [][]byte
	for i := 0; i < reps; i++ {
		ti := (sizeIdx*7 + i) % len(types)
		gen := types[ti].gen
		if onlyType != "" {
			idx, g, ok := typeByName(onlyType)
			if !ok {
				break
			}
			ti, gen = idx, g
		}
		seed := cellSeed(gridMasterSeed, ti, sizeIdx, i)
		data := gen(rand.New(rand.NewPCG(seed, 0)), reqSize)
		if len(data) >= MinFileSize {
			pool = append(pool, data)
		}
	}
	benchBufCache[key] = pool
	return pool
}

func benchReps(rung gridSize) int {
	r := scaledReps(rung.reps)
	if r > benchPoolMax {
		r = benchPoolMax
	}
	return r
}

func avgLen(pool [][]byte) int64 {
	var t int64
	for _, b := range pool {
		t += int64(len(b))
	}
	if len(pool) == 0 {
		return 0
	}
	return t / int64(len(pool))
}

// BenchmarkStreamHash — stream digest by size (mixed types, or -grid.type).
func BenchmarkStreamHash(b *testing.B) {
	for si, rung := range gridSizeLadder {
		if rung.bytes > *flagGridMax {
			continue
		}
		pool := benchBuffers(si, rung.bytes, benchReps(rung), *flagGridType)
		if len(pool) == 0 {
			continue
		}
		b.Run(rung.name, func(b *testing.B) {
			b.SetBytes(avgLen(pool))
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				f, err := New(pool[n%len(pool)])
				if err != nil {
					b.Fatal(err)
				}
				if _, err := f.Compute(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDDHash — DD digest by size × block size.
func BenchmarkDDHash(b *testing.B) {
	for si, rung := range gridSizeLadder {
		if rung.bytes > *flagGridMax {
			continue
		}
		pool := benchBuffers(si, rung.bytes, benchReps(rung), *flagGridType)
		if len(pool) == 0 {
			continue
		}
		for _, blk := range ddBlocksFor(rung.bytes) {
			blk := blk
			name := fmt.Sprintf("%s/blk%dK", rung.name, blk/1024)
			b.Run(name, func(b *testing.B) {
				b.SetBytes(avgLen(pool))
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					f, err := New(pool[n%len(pool)])
					if err != nil {
						b.Fatal(err)
					}
					if _, err := f.WithBlockSize(uint32(blk)).Compute(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// benchDigestPairs builds all ordered replicate-pair digest handles for a type
// pair at the (clamped) scoring anchor in the given mode.
func benchDigestPairs(pair [2]string, mode string, block int) ([]Sdbf, [][2]int) {
	rung, rungIdx := anchorRung()
	reps := scaledReps(rung.reps)
	if reps > benchPoolMax {
		reps = benchPoolMax
	}
	as := buildDigests(pair[0], rungIdx, rung.bytes, reps, mode, block)
	bs := buildDigests(pair[1], rungIdx, rung.bytes, reps, mode, block)
	if len(as) == 0 || len(bs) == 0 {
		return nil, nil
	}
	// Flatten into one digest slice with index pairs referring into it.
	all := make([]Sdbf, 0, len(as)+len(bs))
	for _, d := range as {
		all = append(all, d.sd)
	}
	off := len(all)
	for _, d := range bs {
		all = append(all, d.sd)
	}
	var pairs [][2]int
	for i := range as {
		for j := range bs {
			pairs = append(pairs, [2]int{i, off + j})
		}
	}
	return all, pairs
}

func benchScore(b *testing.B, mode string, block int, ref bool) {
	for _, pair := range scoringSweepPairs {
		all, pairs := benchDigestPairs(pair, mode, block)
		if len(pairs) == 0 {
			continue
		}
		name := pair[0] + "_" + pair[1]
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				p := pairs[n%len(pairs)]
				if ref {
					all[p[0]].CompareRef(all[p[1]])
				} else {
					all[p[0]].Compare(all[p[1]])
				}
			}
		})
	}
}

// BenchmarkStreamScore — exact Compare on stream digests, per type pair.
func BenchmarkStreamScore(b *testing.B) { benchScore(b, "stream", 0, false) }

// BenchmarkDDScore — exact Compare on DD digests (anchor block), per type pair.
func BenchmarkDDScore(b *testing.B) { benchScore(b, "dd", scoringAnchorDDBlock, false) }

// BenchmarkStreamScoreRef — C++-reference staged-early-exit path, per type pair,
// for A/B against the exact path.
func BenchmarkStreamScoreRef(b *testing.B) { benchScore(b, "stream", 0, true) }

// BenchmarkAndPopcount — the innermost 256-byte AND-popcount kernel, on two
// live filters from a feature-rich digest. Ported from the retired bench_test.go.
func BenchmarkAndPopcount(b *testing.B) {
	var si64k int
	for i, rung := range gridSizeLadder {
		if rung.name == "64K" {
			si64k = i
		}
	}
	dig := buildDigests("random", si64k, 64*1024, 1, "stream", 0)
	if len(dig) == 0 {
		b.Skip("no digest")
	}
	sd := dig[0].sd.(*sdbf)
	if sd.bfCount < 2 {
		b.Skip("need two filters")
	}
	bf1 := sd.buffer[0:bfSize]
	bf2 := sd.buffer[bfSize : 2*bfSize]
	b.ReportAllocs()
	b.ResetTimer()
	var sink uint32
	for n := 0; n < b.N; n++ {
		sink += andPopcount(bf1, bf2)
	}
	_ = sink
}
