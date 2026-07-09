package sdhash

import "fmt"

// populateSdbf fills in the mode-specific state of sd by computing ranks,
// scores, and hashes from buffer. It is separated from createSdbf so that
// tests can pass a deliberately broken *sdbf to exercise the error-return
// paths in both stream and block mode.
//
// IMPORTANT: Do not add a default index bloom filter here. Adding one causes
// hash mismatches with the reference implementation.
func populateSdbf(sd *sdbf, buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = maxElem
		if err := sd.generateChunkSdbf(buffer, 32*mB); err != nil {
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
		if err := sd.generateBlockSdbf(buffer); err != nil {
			return nil, err
		}
	}
	sd.computeHamming()
	return sd, nil
}

// createSdbf creates and digests a sdbf from a byte buffer.
func createSdbf(buffer []byte, ddBlockSize uint32) (*sdbf, error) {
	return populateSdbf(&sdbf{
		bfSize:         bfSize,
		bfCount:        1,
		bigFilters:     []*bloomFilter{mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)},
		popWinSize:     popWinSize,
		threshold:      threshold,
		blockSize:      blockSize,
		entropyWinSize: entropyWinSize,
	}, buffer, ddBlockSize)
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

// New returns a factory that will produce a Sdbf from the given byte slice.
// The slice must be at least MinFileSize bytes.
func New(buffer []byte) (SdbfFactory, error) {
	if len(buffer) < MinFileSize {
		return nil, fmt.Errorf("buffer length must be at least %d bytes", MinFileSize)
	}
	// Copy the caller's buffer so the factory is truly independent of
	// external mutations. The cost is negligible relative to Compute.
	buf := make([]byte, len(buffer))
	copy(buf, buffer)
	return &sdbfFactory{
		buffer: buf,
	}, nil
}

// NewRef returns a factory that produces a Sdbf using the C++-reference-
// compatible construction path (the pre-fix chunk-score feature selection).
// It is the construction-side analogue of CompareRef: it exists during the
// reference correctness phase so external harnesses can compare the Go
// library's digests byte-for-byte against the C++ reference via CSV diffing.
//
// Deprecated: NewRef will be removed when C++ reference compatibility is
// dropped at 1.0.0. New code should use New, which produces the modern digest.
//
//goland:noinspection GoDeprecation
func NewRef(buffer []byte) (SdbfFactory, error) {
	if len(buffer) < MinFileSize {
		return nil, fmt.Errorf("buffer length must be at least %d bytes", MinFileSize)
	}
	buf := make([]byte, len(buffer))
	copy(buf, buffer)
	return &sdbfFactoryRef{
		buffer: buf,
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
