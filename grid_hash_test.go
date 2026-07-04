//go:build grid

package sdhash

// Profiling grid — Layer 3 hashing collector.
//
// TestGridHashSerial      per-op distribution, one file at a time, New and
//                         Compute timed separately, stream + DD block ladder.
//                         Rows tagged with digest shape → sliceable by type
//                         (isolated) or aggregated (mixed), and by size.
//
// TestGridHashConcurrent  throughput + latency under a worker pool at swept
//                         widths, over a resident mixed batch (or one type via
//                         -grid.type). Stresses chunkSlicePool contention and
//                         internal-vs-external parallelism on the multi-chunk
//                         path. Trace captured when -grid.trace is set.

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// warmupHashing primes the chunkSlicePool, allocator, and page cache so the
// first timed op's cold costs (pool allocation, first-touch faults) don't
// contaminate the distribution. Called before the timed region, outside any
// profile scope.
func warmupHashing() {
	data := genRandom(rand.New(rand.NewPCG(1, 2)), 256*1024)
	for i := 0; i < 3; i++ {
		if f, err := New(data); err == nil {
			_, _ = f.Compute()
		}
		if f, err := New(data); err == nil {
			_, _ = f.WithBlockSize(64 * 1024).Compute()
		}
	}
}

// hashCSVHeader is the schema for the per-op hashing dataset.
var hashCSVHeader = []string{
	"type", "type_idx", "size_name", "req_size", "actual_size", "rep",
	"mode", "dd_block", "new_ns", "compute_ns",
	"filter_count", "max_elem", "density", "sparse_frac", "total_elems", "hamming_mean",
}

func timeNew(data []byte) (SdbfFactory, float64) {
	t0 := time.Now()
	f, err := New(data)
	ns := float64(time.Since(t0).Nanoseconds())
	if err != nil {
		return nil, ns
	}
	return f, ns
}

func timeComputeStream(f SdbfFactory) (Sdbf, float64) {
	t0 := time.Now()
	sd, err := f.Compute()
	ns := float64(time.Since(t0).Nanoseconds())
	if err != nil {
		return nil, ns
	}
	return sd, ns
}

func timeComputeDD(f SdbfFactory, block int) (Sdbf, float64) {
	t0 := time.Now()
	sd, err := f.WithBlockSize(uint32(block)).Compute()
	ns := float64(time.Since(t0).Nanoseconds())
	if err != nil {
		return nil, ns
	}
	return sd, ns
}

// TestGridHashSerial collects the per-op hashing distribution.
func TestGridHashSerial(t *testing.T) {
	items := planGridScaledCapped()
	m := newRunManifest()
	sink := newCSVSink(t, "hash_serial.csv", m, hashCSVHeader)
	defer sink.close()

	// Accumulators for the printed summary.
	streamByType := map[string][]float64{}
	streamBySize := map[string][]float64{}
	ddByBlock := map[int][]float64{}
	newBySize := map[string][]float64{}

	warmupHashing()
	ps := startProfileScope(t, "hash_serial", false)
	for _, it := range items {
		data := it.generate()
		if len(data) < MinFileSize {
			continue
		}
		actual := len(data)

		// Stream
		f, newNs := timeNew(data)
		if f == nil {
			continue
		}
		sd, compNs := timeComputeStream(f)
		if sd == nil {
			continue
		}
		ss := shapeOf(sd, "stream", 0)
		sink.row(
			it.typeName, fI(it.typeIdx), it.sizeName, fI(it.reqSize), fI(actual), fI(it.rep),
			"stream", fI(0), fF(newNs), fF(compNs),
			fU(uint64(ss.filterCount)), fU(uint64(ss.maxElem)), fF(ss.density), fF(ss.sparseFrac),
			fU(ss.totalElems), fF(ss.hammingMean),
		)
		streamByType[it.typeName] = append(streamByType[it.typeName], compNs)
		streamBySize[it.sizeName] = append(streamBySize[it.sizeName], compNs)
		newBySize[it.sizeName] = append(newBySize[it.sizeName], newNs)

		// DD across the block ladder
		for _, blk := range ddBlocksFor(actual) {
			df, dNewNs := timeNew(data)
			if df == nil {
				continue
			}
			dd, dCompNs := timeComputeDD(df, blk)
			if dd == nil {
				continue
			}
			ds := shapeOf(dd, "dd", blk)
			sink.row(
				it.typeName, fI(it.typeIdx), it.sizeName, fI(it.reqSize), fI(actual), fI(it.rep),
				"dd", fI(blk), fF(dNewNs), fF(dCompNs),
				fU(uint64(ds.filterCount)), fU(uint64(ds.maxElem)), fF(ds.density), fF(ds.sparseFrac),
				fU(ds.totalElems), fF(ds.hammingMean),
			)
			ddByBlock[blk] = append(ddByBlock[blk], dCompNs)
		}
	}
	ps.stop(t)

	// Printed summary.
	t.Logf("=== hash serial: stream Compute by type ===")
	for _, ty := range sortedKeys(streamByType) {
		t.Logf("  %-24s %s", ty, summarize(streamByType[ty]))
	}
	t.Logf("=== hash serial: stream Compute by size ===")
	for _, sz := range ladderOrder(streamBySize) {
		t.Logf("  %-6s %s", sz, summarize(streamBySize[sz]))
		t.Logf("%s", logHistogram(streamBySize[sz], 40))
	}
	t.Logf("=== hash serial: New (buffer copy) by size ===")
	for _, sz := range ladderOrder(newBySize) {
		t.Logf("  %-6s %s", sz, summarize(newBySize[sz]))
	}
	t.Logf("=== hash serial: DD Compute by block ===")
	for _, blk := range sortedIntKeys(ddByBlock) {
		t.Logf("  block=%-8d %s", blk, summarize(ddByBlock[blk]))
	}
}

// residentFile is a materialized batch entry for concurrent runs.
type residentFile struct {
	typeName string
	sizeName string
	data     []byte
}

// buildResidentBatch materializes files from the plan into memory up to the
// membudget, optionally restricted to a single type. Files are interleaved
// across types/sizes so the batch is a realistic mixed pool.
func buildResidentBatch(t *testing.T, budget int64, onlyType string) []residentFile {
	items := planGridScaledCapped()
	// Interleave: iterate replicate-major so early files span many types/sizes.
	var batch []residentFile
	var used int64
	for _, it := range items {
		if onlyType != "" && it.typeName != onlyType {
			continue
		}
		if used+int64(it.reqSize) > budget {
			continue // skip oversized-for-budget, keep filling with smaller ones
		}
		data := it.generate()
		if len(data) < MinFileSize {
			continue
		}
		batch = append(batch, residentFile{it.typeName, it.sizeName, data})
		used += int64(len(data))
	}
	t.Logf("resident batch: %d files, %.1f MiB (budget %.1f MiB, type=%q)",
		len(batch), float64(used)/(1<<20), float64(budget)/(1<<20), onlyType)
	return batch
}

// TestGridHashConcurrent measures stream-hash throughput and latency under a
// worker pool at swept widths.
func TestGridHashConcurrent(t *testing.T) {
	batch := buildResidentBatch(t, *flagGridMemBudget, *flagGridType)
	if len(batch) == 0 {
		t.Skip("empty resident batch")
	}
	m := newRunManifest()
	sink := newCSVSink(t, "hash_concurrent.csv", m,
		[]string{"width", "files", "bytes", "wall_ns", "throughput_mbps", "files_per_sec", "lat_p50_ns", "lat_p99_ns"})
	defer sink.close()

	var totalBytes int64
	for _, r := range batch {
		totalBytes += int64(len(r.data))
	}

	warmupHashing()
	for _, w := range gridWidths() {
		lat := make([]float64, len(batch))
		var idx int64 = -1
		ps := startProfileScope(t, fmt.Sprintf("hash_concurrent_w%d", w), true)
		wall0 := time.Now()
		var wg sync.WaitGroup
		for g := 0; g < w; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(atomic.AddInt64(&idx, 1))
					if i >= len(batch) {
						return
					}
					t0 := time.Now()
					f, err := New(batch[i].data)
					if err != nil {
						continue
					}
					if _, err := f.Compute(); err != nil {
						continue
					}
					lat[i] = float64(time.Since(t0).Nanoseconds())
				}
			}()
		}
		wg.Wait()
		wall := time.Since(wall0)
		ps.stop(t)

		mbps := float64(totalBytes) / (1 << 20) / wall.Seconds()
		fps := float64(len(batch)) / wall.Seconds()
		st := summarize(lat)
		sink.row(fI(w), fI(len(batch)), fI64(totalBytes), fI64(wall.Nanoseconds()),
			fF(mbps), fF(fps), fF(st.p50), fF(st.p99))
		t.Logf("width=%-4d wall=%-12s throughput=%7.1f MiB/s files/s=%8.1f  latency: %s",
			w, wall.String(), mbps, fps, st)
	}
}
