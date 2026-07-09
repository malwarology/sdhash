package sdhash

// Toggle-gated construction path for the reference-correctness investigation.
//
// NewDebug mirrors the modern construction chain but routes feature selection
// through generateChunkScoresDebug, which reverts to the C++-faithful
// double-count behavior when DebugRevertChunkScoresDoubleCount is set (see
// debug.go for the toggle). Used by the handoff test harness to emit modern and
// reference digests from a single API for CSV comparison.
//
// Not part of the public API. This entire file, including NewDebug, will be
// removed when the reference-correctness methodology absorbs into the formal
// unit tests.

import (
	"fmt"
	"runtime"
	"sync"
)

// NewDebug returns a factory that produces a Sdbf using the toggle-gated
// construction path. See DebugRevertChunkScoresDoubleCount.
func NewDebug(buffer []byte) (SdbfFactory, error) {
	if len(buffer) < MinFileSize {
		return nil, fmt.Errorf("buffer length must be at least %d bytes", MinFileSize)
	}
	buf := make([]byte, len(buffer))
	copy(buf, buffer)
	return &sdbfFactoryDebug{
		buffer: buf,
	}, nil
}

type sdbfFactoryDebug struct {
	buffer      []byte
	ddBlockSize uint32
}

func (sdf *sdbfFactoryDebug) WithBlockSize(blockSize uint32) SdbfFactory {
	return &sdbfFactoryDebug{
		buffer:      sdf.buffer,
		ddBlockSize: blockSize,
	}
}

func (sdf *sdbfFactoryDebug) Compute() (Sdbf, error) {
	return createSdbfDebug(sdf.buffer, sdf.ddBlockSize)
}

func createSdbfDebug(buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	return populateSdbfDebug(&sdbf{
		bfSize:         bfSize,
		bfCount:        1,
		bigFilters:     []*bloomFilter{mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)},
		popWinSize:     popWinSize,
		threshold:      threshold,
		blockSize:      blockSize,
		entropyWinSize: entropyWinSize,
	}, buffer, ddBlockSize)
}

func populateSdbfDebug(sd *sdbf, buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = maxElem
		if err := sd.generateChunkSdbfDebug(buffer, 32*mB); err != nil {
			return nil, err
		}
	} else { // block mode
		if ddBlockSize < popWinSize {
			return nil, fmt.Errorf("block size %d is less than minimum %d", ddBlockSize, popWinSize)
		}
		sd.maxElem = maxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize%uint64(ddBlockSize) >= MinFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.buffer = make([]byte, ddBlockCnt*uint64(bfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		if err := sd.generateBlockSdbfDebug(buffer); err != nil {
			return nil, err
		}
	}
	sd.computeHamming()
	return sd, nil
}

func (sd *sdbf) generateChunkSdbfDebug(fileBuffer []byte, chunkSize uint64) error {
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
			sd.generateChunkScoresDebug(chunkRanks, chunkSize, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, 0, chunkScores, chunkSize)
		} else if rem > 0 {
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
			sd.generateChunkScoresDebug(chunkRanks, rem, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, qt*chunkSize, chunkScores, rem)
		}

		if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
			sd.bfCount--
			sd.lastCount = sd.maxElem
		}
		if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
			sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
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

	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			defer captureGoroutinePanic(&panicErr, &panicOnce)
			ranks := getChunkSlice(int(chunkSize))
			scores := getChunkSlice(int(chunkSize))
			sd.generateChunkRanks(fileBuffer[chunkSize*idx:chunkSize*(idx+1)], ranks)
			sd.generateChunkScoresDebug(ranks, chunkSize, scores, nil)
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
			sd.generateChunkScoresDebug(ranks, rem, scores, nil)
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
	return nil
}

func (sd *sdbf) generateBlockSdbfDebug(fileBuffer []byte) error {
	blockSize := uint64(sd.ddBlockSize)
	qt := uint64(len(fileBuffer)) / blockSize
	rem := uint64(len(fileBuffer)) % blockSize

	var (
		panicErr  error
		panicOnce sync.Once
	)

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			defer captureGoroutinePanic(&panicErr, &panicOnce)
			sd.generateSingleBlockSdbfDebug(fileBuffer[blockSize*idx:blockSize*(idx+1)], idx)
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
		sd.generateChunkScoresDebug(chunkRanks, rem, chunkScores, nil)
		sd.generateBlockHash(remBuffer, qt, chunkScores, uint32(rem), sd.threshold, int32(sd.maxElem))
	}
	return nil
}

func (sd *sdbf) generateSingleBlockSdbfDebug(fileBuffer []byte, blockNum uint64) {
	blockSize := uint64(sd.ddBlockSize)
	var sum, allowed uint32
	var scoreHistogram [66]int32
	chunkRanks := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkRanks)
	chunkScores := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkScores)

	sd.generateChunkRanks(fileBuffer, chunkRanks)
	sd.generateChunkScoresDebug(chunkRanks, blockSize, chunkScores, scoreHistogram[:])
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

// generateChunkScoresDebug is the toggle-gated feature selector. With
// DebugRevertChunkScoresDoubleCount false (the default) it produces the modern
// one-increment-per-window output identical to generateChunkScores. When true
// it reverts to the C++-faithful two-block algorithm, including the Block A
// double-count.
func (sd *sdbf) generateChunkScoresDebug(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := uint64(sd.popWinSize)

	if DebugRevertChunkScoresDoubleCount {
		// C++-faithful: two-block algorithm with the Block A double-count.
		var minPos uint64
		minRank := chunkRanks[minPos]
		for i := uint64(0); chunkSize > popWin && i < chunkSize-popWin; i++ {
			if i > 0 && minRank > 0 {
				for i < chunkSize-popWin && i < minPos && chunkRanks[i+popWin] >= minRank {
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
	} else {
		// Modern: one increment per window, no double-count.
		for i := uint64(0); chunkSize > popWin && i < chunkSize-popWin; i++ {
			minPos := i
			minRank := chunkRanks[minPos]
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
	}

	if scoreHistogram != nil {
		for i := uint64(0); i < chunkSize-popWin; i++ {
			scoreHistogram[chunkScores[i]]++
		}
	}
}
