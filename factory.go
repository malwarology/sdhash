package sdhash

import "fmt"

// createSdbf creates and digests a sdbf from a byte buffer. Configuration is
// snapshotted from the package-level defaults at this point; subsequent changes
// to the defaults do not affect this digest.
//
// IMPORTANT: Do not add a default index bloom filter here. Adding one causes
// hash mismatches with the reference implementation.
func createSdbf(buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	sd := &sdbf{
		bfSize:         BfSize,
		bfCount:        1,
		bigFilters:     []*bloomFilter{mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)},
		popWinSize:     PopWinSize,
		threshold:      Threshold,
		blockSize:      BlockSize,
		entropyWinSize: EntropyWinSize,
	}

	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = MaxElem
		sd.generateChunkSdbf(buffer, 32*mB)
	} else { // block mode
		sd.maxElem = MaxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize%uint64(ddBlockSize) >= MinFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.buffer = make([]byte, ddBlockCnt*uint64(BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.generateBlockSdbf(buffer)
	}
	sd.computeHamming()

	return sd, nil
}

// SdbfFactory creates a Sdbf digest from a binary source.
// Use WithBlockSize to configure the factory before calling Compute.
//
// Factories are immutable: WithBlockSize returns a new factory rather than
// modifying the receiver, so all methods are inherently safe for concurrent use.
type SdbfFactory interface {

	// WithBlockSize sets the block size for block-aligned (dd) mode and returns
	// a new factory with that configuration applied. A value of 0 (the default)
	// produces a digest in stream mode.
	WithBlockSize(blockSize uint32) SdbfFactory

	// Compute runs the digesting process and returns the resulting Sdbf.
	Compute() (Sdbf, error)
}

type sdbfFactory struct {
	buffer      []byte
	ddBlockSize uint32
}

// CreateSdbfFromBytes returns a factory that will produce a Sdbf from the given byte slice.
// The slice must be at least MinFileSize bytes.
func CreateSdbfFromBytes(buffer []byte) (SdbfFactory, error) {
	if len(buffer) < MinFileSize {
		return nil, fmt.Errorf("buffer length must be at least %d bytes", MinFileSize)
	}
	return &sdbfFactory{
		buffer: buffer,
	}, nil
}

// WithBlockSize returns a new factory with the given block size configured.
// It does not modify the receiver.
func (sdf *sdbfFactory) WithBlockSize(blockSize uint32) SdbfFactory {
	return &sdbfFactory{
		buffer:      sdf.buffer,
		ddBlockSize: blockSize,
	}
}

func (sdf *sdbfFactory) Compute() (Sdbf, error) {
	return createSdbf(sdf.buffer, sdf.ddBlockSize)
}
