package sdhash

// C++-reference-compatible construction path.
//
// This file mirrors the modern digest-construction chain (New/Compute) but
// substitutes the pre-fix generateChunkScoresRef feature-selection function,
// reproducing the C++ reference's chunk-score behavior (including the Block A
// double-count) for byte-for-byte handoff comparison. Everything else in the
// chain (ranks, hashing, hamming, bloom, goroutine pool) is shared, unchanged,
// with the modern path.
//
// Deprecated: this entire file will be removed when C++ reference compatibility
// is dropped at 1.0.0. The public entry point NewRef lives beside New in
// factory.go and is likewise deprecated.

import (
	"fmt"
	"runtime"
	"sync"
)

// sdbfFactoryRef is the reference-path analogue of sdbfFactory; its Compute
// routes through createSdbfRef.
type sdbfFactoryRef struct {
	buffer      []byte
	ddBlockSize uint32
}

func (sdf *sdbfFactoryRef) WithBlockSize(blockSize uint32) SdbfFactory {
	return &sdbfFactoryRef{
		buffer:      sdf.buffer,
		ddBlockSize: blockSize,
	}
}

func (sdf *sdbfFactoryRef) Compute() (Sdbf, error) {
	return createSdbfRef(sdf.buffer, sdf.ddBlockSize)
}

func createSdbfRef(buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	return populateSdbfRef(&sdbf{
		bfSize:         bfSize,
		bfCount:        1,
		bigFilters:     []*bloomFilter{mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)},
		popWinSize:     popWinSize,
		threshold:      threshold,
		blockSize:      blockSize,
		entropyWinSize: entropyWinSize,
	}, buffer, ddBlockSize)
}

func populateSdbfRef(sd *sdbf, buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = maxElem
		if err := sd.generateChunkSdbfRef(buffer, 32*mB); err != nil {
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
		if err := sd.generateBlockSdbfRef(buffer); err != nil {
			return nil, err
		}
	}
	sd.computeHamming()
	return sd, nil
}

func (sd *sdbf) generateChunkSdbfRef(fileBuffer []byte, chunkSize uint64) error {
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
			sd.generateChunkScoresRef(chunkRanks, chunkSize, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, 0, chunkScores, chunkSize)
		} else if rem > 0 {
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
			sd.generateChunkScoresRef(chunkRanks, rem, chunkScores, nil)
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
			sd.generateChunkScoresRef(ranks, chunkSize, scores, nil)
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
			sd.generateChunkScoresRef(ranks, rem, scores, nil)
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

func (sd *sdbf) generateBlockSdbfRef(fileBuffer []byte) error {
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
			sd.generateSingleBlockSdbfRef(fileBuffer[blockSize*idx:blockSize*(idx+1)], idx)
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
		sd.generateChunkScoresRef(chunkRanks, rem, chunkScores, nil)
		sd.generateBlockHash(remBuffer, qt, chunkScores, uint32(rem), sd.threshold, int32(sd.maxElem))
	}
	return nil
}

func (sd *sdbf) generateSingleBlockSdbfRef(fileBuffer []byte, blockNum uint64) {
	blockSize := uint64(sd.ddBlockSize)
	var sum, allowed uint32
	var scoreHistogram [66]int32
	chunkRanks := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkRanks)
	chunkScores := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkScores)

	sd.generateChunkRanks(fileBuffer, chunkRanks)
	sd.generateChunkScoresRef(chunkRanks, blockSize, chunkScores, scoreHistogram[:])
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

func (sd *sdbf) generateChunkScoresRef(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := uint64(sd.popWinSize)
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
	if scoreHistogram != nil {
		for i := uint64(0); i < chunkSize-popWin; i++ {
			scoreHistogram[chunkScores[i]]++
		}
	}
}
