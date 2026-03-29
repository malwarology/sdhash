package sdhash

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// u32sha1 computes the SHA1 of data and returns it as five little-endian uint32 values.
func u32sha1(data []uint8) [5]uint32 {
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
	}
	return make([]uint16, size)
}

// putChunkSlice returns a slice to the pool for reuse. The caller must not
// retain any reference to the slice after this call.
func putChunkSlice(s []uint16) {
	chunkSlicePool.Put(&s)
}

// generateChunkRanks generates entropy-based ranks for each position in fileBuffer.
//
// OPTIMIZATION HISTORY: Re-slicing chunkRanks at function entry to hint
// bounds check elimination (BCE) was attempted and had no effect. The compiler
// cannot eliminate the chunkRanks[offset] check because offset is bounded by
// a computed limit, not by len(chunkRanks) directly. The access pattern is
// already O(n) and the per-element cost is dominated by the entropy table
// lookup and the incremental entropy update, not by bounds checks.
func (sd *sdbf) generateChunkRanks(fileBuffer []uint8, chunkRanks []uint16) {
	var entropy uint64
	ascii := make([]uint8, 256)

	limit := len(fileBuffer) - sd.entropyWinSize
	for offset := 0; offset < limit; offset++ {
		if offset%sd.blockSize == 0 { // full entropy recalculation at block boundaries
			entropy = entropy64InitInt(fileBuffer[offset:], ascii)
		} else { // incremental rolling update
			entropy = entropy64IncInt(entropy, fileBuffer[offset-1:], ascii)
		}
		chunkRanks[offset] = uint16(entropy64Ranks[entropy>>entropyPower])
	}
}

// generateChunkScores generates scores for each position in a ranked chunk
// using a sliding minimum window.
//
// OPTIMIZATION HISTORY: This function is 50% of total CPU time. Three
// approaches to reduce that cost were evaluated and all failed:
//
//  1. BCE via re-slicing inputs at function entry: no effect. The compiler
//     cannot prove i+popWin < chunkSize because popWin is a runtime value.
//
//  2. BCE via range over sub-slices in the j-loop: reduced check count for
//     that loop but had no measurable effect on runtime. The hot checks —
//     chunkRanks[i+popWin] in the inner while-loop and chunkRanks[minPos] /
//     chunkScores[minPos] — are structurally unreachable by BCE because
//     minPos is assigned inside loop bodies and i mutates inside the inner
//     while body.
//
//  3. Algorithmic replacement with a monotonic deque O(n) sliding window
//     minimum: ruled out. The original algorithm is not a pure sliding
//     window minimum — the inner while-loop reuses the previous window's
//     minPos and scores it incrementally, producing different minPos
//     assignments than a deque. The corpus tests (digest-exact match against
//     C++ reference) would fail. Additionally, the algorithm is already
//     O(n) amortized on real entropy data because the inner while
//     fast-forwards i until the minimum expires.
//
// The remaining cost is irreducible algorithmic work: rank comparisons and
// memory accesses across the entropy-ranked data. Parallelism at the file
// level (already implemented) is the correct lever for throughput.
func (sd *sdbf) generateChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := uint64(sd.popWinSize)
	var minPos uint64
	minRank := chunkRanks[minPos]

	for i := uint64(0); chunkSize > popWin && i < chunkSize-popWin; i++ {
		if i > 0 && minRank > 0 {
			for chunkRanks[i+popWin] >= minRank && i < minPos && i < chunkSize-popWin+1 {
				if chunkRanks[i+popWin] == minRank {
					minPos = i + popWin
				}
				chunkScores[minPos]++
				i++
			}
		}
		minPos = i
		minRank = chunkRanks[minPos]
		for j := i + 1; j < i+popWin; j++ {
			if chunkRanks[j] < minRank && chunkRanks[j] > 0 {
				minRank = chunkRanks[j]
				minPos = j
			} else if minPos == j-1 && chunkRanks[j] == minRank {
				minPos = j
			}
		}
		if chunkRanks[minPos] > 0 {
			chunkScores[minPos]++
		}
	}
	if scoreHistogram != nil {
		for i := uint64(0); i < chunkSize-popWin; i++ {
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
// PROFILING NOTE: SHA1 accounts for roughly 5% of total CPU time. The
// dominant costs are generateChunkScores (50%) and slice zeroing (25%).
// Optimizing SHA1 would have negligible impact on overall throughput.
func (sd *sdbf) generateChunkHash(fileBuffer []uint8, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.buffer[(bfCount-1)*sd.bfSize:]
	currentBigFilter := sd.bigFilters[len(sd.bigFilters)-1]
	var bigFilterElemCount uint64

	if chunkSize > uint64(sd.popWinSize) {
		for i := uint64(0); i < chunkSize-uint64(sd.popWinSize); i++ {
			if uint32(chunkScores[i]) > sd.threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i : chunkPos+i+uint64(sd.popWinSize)])

				// Skip if no new bits were set (repetitive feature).
				if bfSha1Insert(currBf, sha1Hash) == 0 {
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
func (sd *sdbf) generateBlockHash(fileBuffer []uint8, blockNum uint64, chunkScores []uint16, rem uint32,
	threshold uint32, allowed int32) {
	var hashCnt uint32
	maxOffset := sd.ddBlockSize
	if rem > 0 {
		maxOffset = rem
	}
	for i := uint32(0); i < maxOffset-sd.popWinSize && hashCnt < sd.maxElem; i++ {
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
			sha1Hash := u32sha1(fileBuffer[i : i+sd.popWinSize])
			bf := sd.buffer[blockNum*uint64(sd.bfSize) : (blockNum+1)*uint64(sd.bfSize)]
			if bfSha1Insert(bf, sha1Hash) == 0 { // skip repetitive features
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

// generateChunkSdbf computes the sdbf hash for a buffer in stream mode.
//
// For files spanning more than one chunk the work is split into two phases:
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
func (sd *sdbf) generateChunkSdbf(fileBuffer []uint8, chunkSize uint64) {
	if chunkSize <= uint64(sd.popWinSize) {
		panic(fmt.Sprintf("chunkSize %d must be greater than popWinSize %d", chunkSize, sd.popWinSize))
	}

	fileSize := uint64(len(fileBuffer))
	buffSize := ((fileSize >> 11) + 1) << 8 // initial sdbf buffer estimate
	sd.buffer = make([]uint8, buffSize)

	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	totalChunks := qt
	if rem > 0 {
		totalChunks++
	}

	// Single-chunk fast path: skip parallel overhead entirely.
	if totalChunks <= 1 {
		chunkRanks := getChunkSlice(int(chunkSize))
		defer putChunkSlice(chunkRanks)
		chunkScores := getChunkSlice(int(chunkSize))
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
		if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
			sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
		}
		return
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

	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
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

	// Phase 2: sequential hash insertion in original chunk order.
	// generateChunkHash is called in exactly the same order (0, 1, 2, … qt,
	// rem) as the original loop, so bigFilter cross-chunk deduplication is
	// preserved without any change to that function.
	var chunkPos uint64
	for i := uint64(0); i < totalChunks; i++ {
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
	if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
		sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
	}
}

// generateSingleBlockSdbf is the goroutine worker for parallel block hash generation.
func (sd *sdbf) generateSingleBlockSdbf(fileBuffer []uint8, blockNum uint64) {
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
func (sd *sdbf) generateBlockSdbf(fileBuffer []uint8) {
	blockSize := uint64(sd.ddBlockSize)
	qt := uint64(len(fileBuffer)) / blockSize
	rem := uint64(len(fileBuffer)) % blockSize

	var wg sync.WaitGroup
	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		go func(idx uint64) {
			defer wg.Done()
			sd.generateSingleBlockSdbf(fileBuffer[blockSize*idx:blockSize*(idx+1)], idx)
		}(i)
	}
	wg.Wait()

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
}

// sdbfScore calculates the similarity score (0–100) between two sdbf digests.
// Both digests must have their hamming weights pre-computed (guaranteed after construction).
// The caller must hold at least read locks on both sdbf1 and sdbf2.
func sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf, sample uint32) int {
	bfCount1 := sdbf1.bfCount
	if sample > 0 && bfCount1 > sample {
		bfCount1 = sample
	}

	// Always iterate over the smaller digest. This minimizes the number of
	// sdbfMaxScore calls while still finding the best match for every filter
	// in the smaller digest against the full larger digest.
	if bfCount1 > sdbf2.bfCount {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 == 0 {
		return -1
	}

	var scoreSum float64
	var sparseCount uint32
	for i := uint32(0); i < bfCount1; i++ {
		scoreSum += sdbfMaxScore(sdbf1, i, sdbf2)
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	denominator := bfCount1
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	if denominator == 0 {
		scoreSum--
	}

	if scoreSum < 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScore calculates the maximum match of a single reference filter against all target filters.
// Returns 0 if the reference filter has too few elements for a valid comparison, -1 if no target
// filter had enough elements to score against, or a value in [0.0, 1.0] otherwise.
// The caller must hold at least read locks on both refSdbf and targetSdbf.
func sdbfMaxScore(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
	var maxScore float64 = -1
	bfSize := refSdbf.bfSize

	s1 := refSdbf.elemCount(refIndex)
	if s1 < minElemCount {
		return 0
	}
	bf1 := refSdbf.buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.buffer[i*bfSize:]
		s2 := targetSdbf.elemCount(i)
		if s2 < minElemCount {
			continue
		}
		e2Cnt := targetSdbf.hamming[i]
		maxEst := min(e1Cnt, e2Cnt)
		cutOff := cutoffs256[4096/(s1+s2)]
		var score float64
		match := andPopcount(bf1, bf2)
		if match > cutOff {
			score = float64(match-cutOff) / float64(uint32(maxEst)-cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}
