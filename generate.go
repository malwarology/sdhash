package sdhash

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
)

// u32sha1 computes the SHA1 of data and returns it as five little-endian uint32 values.
func u32sha1(data []byte) [5]uint32 {
	sum := sha1.Sum(data)

	var buf [5]uint32
	for i := range buf {
		buf[i] = binary.LittleEndian.Uint32(sum[i*4 : (i+1)*4])
	}

	return buf
}

// chunkSlicePool reuses []uint16 backing arrays across generateChunkRanks /
// generateChunkScores calls to eliminate the dominant make() + GC overhead.
var chunkSlicePool = sync.Pool{
	New: func() any {
		return (*[]uint16)(nil)
	},
}

// getChunkSlice returns a zeroed []uint16 of the given length, reusing a
// pooled backing array when one of sufficient capacity is available.
func getChunkSlice(size int) []uint16 {
	if v := chunkSlicePool.Get(); v != nil {
		if sp := v.(*[]uint16); sp != nil && cap(*sp) >= size {
			s := (*sp)[:size]
			clear(s)
			return s
		}
		// Undersized slice intentionally dropped — returning it to the pool
		// would permanently pollute it with slices too small to reuse.
	}
	return make([]uint16, size)
}

// putChunkSlice returns a slice to the pool for reuse. The caller must not
// retain any reference to the slice after this call.
func putChunkSlice(s []uint16) {
	chunkSlicePool.Put(&s)
}

// indexSlicePool reuses []int32 backing arrays for the generateChunkScores
// runEnd scratch, avoiding a per-chunk allocation proportional to chunk size.
var indexSlicePool = sync.Pool{
	New: func() any {
		return (*[]int32)(nil)
	},
}

// getIndexSlice returns a []int32 of the given length, reusing a pooled backing
// array when one large enough is available. Contents are not cleared; the
// caller fully overwrites the slice.
func getIndexSlice(size int) []int32 {
	if v := indexSlicePool.Get(); v != nil {
		if sp := v.(*[]int32); sp != nil && cap(*sp) >= size {
			return (*sp)[:size]
		}
	}
	return make([]int32, size)
}

func putIndexSlice(s []int32) {
	indexSlicePool.Put(&s)
}

// asciiPool reuses the 256-byte frequency table used by generateChunkRanks.
// The allocation is small but called per-chunk, so pooling it reduces GC scan
// pressure on high-throughput workloads.
var asciiPool = sync.Pool{
	New: func() any {
		buf := new([]byte)
		*buf = make([]byte, 256)
		return buf
	},
}

// generateChunkRanks generates entropy-based ranks for each position in fileBuffer.
//
// OPTIMIZATION HISTORY: Re-slicing chunkRanks at function entry to hint
// bounds check elimination (BCE) was attempted and had no effect. The compiler
// cannot eliminate the chunkRanks[offset] check because offset is bounded by
// a computed limit, not by len(chunkRanks) directly. The access pattern is
// already O(n) and the per-element cost is dominated by the entropy table
// lookup and the incremental entropy update, not by bounds checks.
func (sd *sdbf) generateChunkRanks(fileBuffer []byte, chunkRanks []uint16) {
	if sd.testFaultHook != nil {
		sd.testFaultHook()
	}
	var entropy uint64
	asciiPtr := asciiPool.Get().(*[]byte)
	ascii := *asciiPtr
	clear(ascii)
	defer asciiPool.Put(asciiPtr)

	limit := len(fileBuffer) - sd.entropyWinSize
	for offset := range limit {
		if offset%blockSize == 0 { // full entropy recalculation at block boundaries
			entropy = entropy64Compute(fileBuffer[offset:], ascii)
		} else { // incremental rolling update
			entropy = entropy64Update(entropy, fileBuffer[offset-1:], ascii)
		}
		chunkRanks[offset] = uint16(entropy64Ranks[entropy>>entropyPower])
	}
}

// generateChunkScores records one selected feature position per sliding window
// in chunkScores. It runs in O(n); see the inline comments for the selection
// rule and the deque construction.
//
// OPTIMIZATION HISTORY: the function was previously an O(n*popWin) per-window
// rescan. Two attempts to speed that rescan up by eliminating bounds checks
// were evaluated, both without measurable effect:
//
//  1. Re-slicing the inputs at function entry to hint bounds-check elimination:
//     no effect. The compiler cannot prove the window index stays in range
//     because popWin is a runtime value.
//
//  2. Ranging over sub-slices in the inner loop: reduced the static check count
//     but did not change runtime; the hot accesses were structurally
//     unreachable by BCE because the selected index was assigned inside the
//     loop body.
//
// The rescan's cost was genuine algorithmic work, not bounds-check overhead, so
// it was replaced by the current monotonic-deque implementation rather than
// micro-optimized.
func (sd *sdbf) generateChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := int(sd.popWinSize)
	n := int(chunkSize)

	// For each window, select one position: the minimum nonzero rank, breaking
	// ties by the rightmost element of the first consecutive run of that value;
	// increment that position once (windows whose left edge is zero contribute
	// nothing). Implemented in O(n): a runEnd precompute plus a monotonic deque
	// whose front is the leftmost minimum-nonzero position of the window.
	if n > popWin {
		// runEnd[k] = last index of the maximal consecutive equal-value run
		// that starts at k. Clipped to the window, runEnd[front] gives the
		// rightmost element of the first run of the minimum value.
		runEnd := getIndexSlice(n)
		defer putIndexSlice(runEnd)
		runEnd[n-1] = int32(n - 1)
		for k := n - 2; k >= 0; k-- {
			if chunkRanks[k] == chunkRanks[k+1] {
				runEnd[k] = runEnd[k+1]
			} else {
				runEnd[k] = int32(k)
			}
		}

		// Monotonic deque as a fixed ring buffer. Values are strictly increasing
		// front-to-back (equal values keep the leftmost at the front), holding
		// only nonzero positions, so the front is the leftmost minimum-nonzero.
		// dqCap is a power of two >= popWinSize+2: the window transiently holds
		// popWin+1 entries, and masking replaces modular arithmetic.
		const dqCap = 128
		const dqMask = dqCap - 1
		var ring [dqCap]int32
		h, tail := 0, 0

		// Seed the deque with the first window [0, popWin).
		for j := range popWin {
			if chunkRanks[j] == 0 {
				continue
			}
			for h != tail && chunkRanks[ring[(tail-1)&dqMask]] > chunkRanks[j] {
				tail = (tail - 1) & dqMask
			}
			ring[tail] = int32(j)
			tail = (tail + 1) & dqMask
		}

		numWindows := n - popWin
		for i := range numWindows {
			// Drop front indices that have fallen out of the window.
			for h != tail && int(ring[h]) < i {
				h = (h + 1) & dqMask
			}
			if chunkRanks[i] != 0 && h != tail {
				minPos := runEnd[ring[h]]
				if int(minPos) > i+popWin-1 {
					minPos = int32(i + popWin - 1)
				}
				chunkScores[minPos]++
			}
			// Admit the incoming right-edge index for the next window.
			if r := i + popWin; r < n && chunkRanks[r] != 0 {
				for h != tail && chunkRanks[ring[(tail-1)&dqMask]] > chunkRanks[r] {
					tail = (tail - 1) & dqMask
				}
				ring[tail] = int32(r)
				tail = (tail + 1) & dqMask
			}
		}
	}

	if scoreHistogram != nil {
		popWinU := uint64(sd.popWinSize)
		for i := range chunkSize - popWinU {
			scoreHistogram[chunkScores[i]]++
		}
	}
}

// generateChunkHash hashes high-scoring positions in fileBuffer and inserts them into the sdbf (stream mode).
//
// NOTE: Do not attempt to parallelize the SHA1 loop below or pipeline the
// hash insertions. This was evaluated and produced no measurable throughput
// gain. The reason is structural: when a multi-worker pool is already
// processing multiple inputs concurrently, the cores stay saturated at the
// file level. Adding within-file parallelism introduces synchronization
// overhead on the bloom filter and bigFilter state without freeing any CPU
// capacity. The sequential loop is the correct design.
//
// PROFILING NOTE: SHA1 accounts for roughly 1–5% of total CPU time
// depending on hardware. The dominant cost is generateChunkScores (50–62%).
// Slice zeroing (memclr from pooled slice reuse) varies from 7% on fast
// desktop cores to 25% on many-core servers. Optimizing SHA1 would have
// negligible impact on overall throughput.
func (sd *sdbf) generateChunkHash(fileBuffer []byte, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.buffer[(bfCount-1)*sd.bfSize:]
	currentBigFilter := sd.bigFilters[len(sd.bigFilters)-1]
	var bigFilterElemCount uint64

	if chunkSize > uint64(sd.popWinSize) {
		for i := range chunkSize - uint64(sd.popWinSize) {
			if uint32(chunkScores[i]) > sd.threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i : chunkPos+i+uint64(sd.popWinSize)])

				// Skip if no new bits were set (repetitive feature).
				if bfInsertSha1(currBf, sha1Hash) == 0 {
					continue
				}

				// Skip if already seen in the large-scale deduplication filter.
				if !currentBigFilter.insertSha1(sha1Hash[:]) {
					continue
				}

				lastCount++
				bigFilterElemCount++
				if lastCount == sd.maxElem {
					currBf = currBf[sd.bfSize:]
					bfCount++
					lastCount = 0
				}
				if bigFilterElemCount == currentBigFilter.maxElem {
					currentBigFilter = mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)
					sd.bigFilters = append(sd.bigFilters, currentBigFilter)
					bigFilterElemCount = 0
				}
			}
		}
	}

	sd.bfCount = bfCount
	sd.lastCount = lastCount
}

// generateBlockHash hashes high-scoring positions in fileBuffer and inserts them into the sdbf (block mode).
func (sd *sdbf) generateBlockHash(fileBuffer []byte, blockNum uint64, chunkScores []uint16, rem uint32,
	threshold uint32, allowed int32) {
	var hashCnt uint32
	maxOffset := sd.ddBlockSize
	if rem > 0 {
		maxOffset = rem
	}
	limit := maxOffset - sd.popWinSize
	for i := uint32(0); i < limit && hashCnt < sd.maxElem; i++ {
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
			sha1Hash := u32sha1(fileBuffer[i : i+sd.popWinSize])
			bf := sd.buffer[blockNum*uint64(sd.bfSize) : (blockNum+1)*uint64(sd.bfSize)]
			if bfInsertSha1(bf, sha1Hash) == 0 { // skip repetitive features
				continue
			}
			hashCnt++
			if uint32(chunkScores[i]) == threshold {
				allowed--
			}
		}
	}

	sd.elemCounts[blockNum] = uint16(hashCnt)
}

// captureGoroutinePanic is deferred inside goroutines spawned by
// generateChunkSdbf and generateBlockSdbf. It recovers any panic and stores
// it as an error, using panicOnce to guarantee only one goroutine writes
// panicErr. Extracting this into a named function gives the coverage tool a
// single closure body to instrument rather than one per goroutine type.
func captureGoroutinePanic(panicErr *error, panicOnce *sync.Once) {
	if r := recover(); r != nil {
		panicOnce.Do(func() {
			*panicErr = fmt.Errorf("panic in goroutine: %v", r)
		})
	}
}

// generateChunkSdbf computes the sdbf hash for a buffer in stream mode.
//
// For files spanning more than one chunk, the work is split into two phases:
//
//   - Phase 1 (parallel): generateChunkRanks and generateChunkScores are
//     pure functions with no shared state, so they are dispatched concurrently
//     across chunks, bounded by runtime.NumCPU() goroutines. Each goroutine
//     operates on its own independent ranks and scores arrays; there is no
//     sharing between chunks.
//
//   - Phase 2 (sequential): generateChunkHash is called in strict chunk order
//     (0, 1, 2, … qt, rem). This preserves the cross-chunk bigFilter
//     deduplication behavior exactly — a feature seen in chunk N is still
//     rejected in chunk N+1, identical to the original sequential loop.
//
// Files that fit in a single chunk skip the parallel machinery entirely and
// follow the original sequential path.
func (sd *sdbf) generateChunkSdbf(fileBuffer []byte, chunkSize uint64) error {
	if chunkSize <= uint64(sd.popWinSize) {
		return fmt.Errorf("chunkSize %d must be greater than popWinSize %d", chunkSize, sd.popWinSize)
	}

	fileSize := uint64(len(fileBuffer))
	buffSize := ((fileSize >> 11) + 1) << 8 // initial sdbf buffer estimate
	sd.buffer = make([]byte, buffSize)

	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	totalChunks := qt
	if rem > 0 {
		totalChunks++
	}

	// Single-chunk fast path: skip parallel overhead entirely.
	if totalChunks <= 1 {
		// Size scratch slices to the actual data, not the 32 MiB chunk cap.
		// For a single chunk the used length is exactly fileSize, so clearing
		// a full chunk-sized slice wastes work proportional to the gap.
		effSize := int(fileSize)
		chunkRanks := getChunkSlice(effSize)
		defer putChunkSlice(chunkRanks)
		chunkScores := getChunkSlice(effSize)
		defer putChunkSlice(chunkScores)

		if qt == 1 {
			sd.generateChunkRanks(fileBuffer[:chunkSize], chunkRanks)
			sd.generateChunkScores(chunkRanks, chunkSize, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, 0, chunkScores, chunkSize)
		} else if rem > 0 {
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
			sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, qt*chunkSize, chunkScores, rem)
		}

		if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
			sd.bfCount--
			sd.lastCount = sd.maxElem
		}
		if newLen := uint64(sd.bfCount) * uint64(sd.bfSize); newLen < buffSize {
			sd.buffer = sd.buffer[:newLen]
		}
		return nil
	}

	// Multi-chunk path.

	// chunkWork holds the pre-computed scores and the effective size for one chunk.
	type chunkWork struct {
		scores []uint16
		size   uint64
	}
	results := make([]chunkWork, totalChunks)

	// Phase 1: parallel rank and score computation.
	// A buffered semaphore limits concurrency to runtime.NumCPU() goroutines.
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	var (
		panicErr  error
		panicOnce sync.Once
	)

	for i := range qt {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			defer captureGoroutinePanic(&panicErr, &panicOnce)
			ranks := getChunkSlice(int(chunkSize))
			scores := getChunkSlice(int(chunkSize))
			sd.generateChunkRanks(fileBuffer[chunkSize*idx:chunkSize*(idx+1)], ranks)
			sd.generateChunkScores(ranks, chunkSize, scores, nil)
			putChunkSlice(ranks)
			results[idx] = chunkWork{scores: scores, size: chunkSize}
		}(i)
	}
	if rem > 0 {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer captureGoroutinePanic(&panicErr, &panicOnce)
			// Allocate ranks at full chunkSize so the slice is always large
			// enough regardless of rem; generateChunkRanks only writes up to
			// len(fileBuffer)-entropyWinSize entries.
			ranks := getChunkSlice(int(chunkSize))
			scores := getChunkSlice(int(chunkSize))
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], ranks)
			sd.generateChunkScores(ranks, rem, scores, nil)
			putChunkSlice(ranks)
			results[qt] = chunkWork{scores: scores, size: rem}
		}()
	}
	wg.Wait()
	if panicErr != nil {
		return panicErr
	}

	// Phase 2: sequential hash insertion in original chunk order.
	// generateChunkHash is called in exactly the same order (0, 1, 2, … qt,
	// rem) as the original loop, so bigFilter cross-chunk deduplication is
	// preserved without any change to that function.
	var chunkPos uint64
	for i := range totalChunks {
		r := results[i]
		sd.generateChunkHash(fileBuffer, chunkPos, r.scores, r.size)
		chunkPos += r.size
		putChunkSlice(r.scores)
	}

	// Drop the last filter if its membership is too low (reduces false positives).
	if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
		sd.bfCount--
		sd.lastCount = sd.maxElem
	}

	// Trim the buffer to the actual used size.
	if newLen := uint64(sd.bfCount) * uint64(sd.bfSize); newLen < buffSize {
		sd.buffer = sd.buffer[:newLen]
	}
	return nil
}

// generateSingleBlockSdbf is the goroutine worker for parallel block hash generation.
func (sd *sdbf) generateSingleBlockSdbf(fileBuffer []byte, blockNum uint64) {
	blockSize := uint64(sd.ddBlockSize)
	var sum, allowed uint32
	var scoreHistogram [66]int32
	chunkRanks := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkRanks)
	chunkScores := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkScores)

	sd.generateChunkRanks(fileBuffer, chunkRanks)
	sd.generateChunkScores(chunkRanks, blockSize, chunkScores, scoreHistogram[:])
	var k uint32
	for k = 65; k >= sd.threshold; k-- {
		if sum <= sd.maxElem && (sum+uint32(scoreHistogram[k]) > sd.maxElem) {
			break
		}
		sum += uint32(scoreHistogram[k])
	}
	allowed = sd.maxElem - sum
	sd.generateBlockHash(fileBuffer, blockNum, chunkScores, 0, k, int32(allowed))
}

// generateBlockSdbf computes the sdbf hash for a buffer in block-aligned (dd) mode.
func (sd *sdbf) generateBlockSdbf(fileBuffer []byte) error {
	blockSize := uint64(sd.ddBlockSize)
	qt := uint64(len(fileBuffer)) / blockSize
	rem := uint64(len(fileBuffer)) % blockSize

	var (
		panicErr  error
		panicOnce sync.Once
	)

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	for i := range qt {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			defer captureGoroutinePanic(&panicErr, &panicOnce)
			sd.generateSingleBlockSdbf(fileBuffer[blockSize*idx:blockSize*(idx+1)], idx)
		}(i)
	}
	wg.Wait()
	if panicErr != nil {
		return panicErr
	}

	if rem >= MinFileSize {
		chunkRanks := getChunkSlice(int(blockSize))
		defer putChunkSlice(chunkRanks)
		chunkScores := getChunkSlice(int(blockSize))
		defer putChunkSlice(chunkScores)

		remBuffer := fileBuffer[blockSize*qt : blockSize*qt+rem]
		sd.generateChunkRanks(remBuffer, chunkRanks)
		sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.generateBlockHash(remBuffer, qt, chunkScores, uint32(rem), sd.threshold, int32(sd.maxElem))
	}
	return nil
}
