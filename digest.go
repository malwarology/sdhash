package sdhash

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"sync"
)

// Sdbf represents the similarity digest of a file or byte buffer. Two Sdbf values
// can be compared to produce a score indicating how similar their source data is.
//
// All methods are safe for concurrent use by multiple goroutines.
type Sdbf interface {

	// Size returns the total byte size of the bloom filter data within this Sdbf.
	Size() uint64

	// InputSize returns the size of the original data this Sdbf was generated from.
	InputSize() uint64

	// FilterCount returns the number of bloom filters in this Sdbf.
	FilterCount() uint32

	// Compare returns a similarity score in [0, 100] between this Sdbf and other.
	// A score of 0 indicates very different data; 100 indicates identical data.
	Compare(other Sdbf) int

	// CompareSample returns a similarity score in [0, 100] using at most sample
	// bloom filters from each digest. Use 0 to disable sampling.
	CompareSample(other Sdbf, sample uint32) int

	// String returns the digest encoded as a string in the sdbf wire format.
	String() string
}

type sdbf struct {
	mu           sync.RWMutex   // protects all fields below for concurrent access
	hamming      []uint16       // hamming weight for each bloom filter; always set after construction
	buffer       []uint8        // concatenated bloom filter data
	maxElem      uint32         // max elements per filter (snapshotted from MaxElem or MaxElemDd)
	bigFilters   []*bloomFilter // large deduplication filters used during stream-mode digesting
	bfCount      uint32         // number of bloom filters
	bfSize       uint32         // bloom filter size in bytes (snapshotted from BfSize)
	lastCount    uint32         // element count in the final filter (stream mode only)
	elemCounts   []uint16       // per-filter element counts (block mode only)
	ddBlockSize  uint32         // block size in block mode
	origFileSize uint64         // size of the original input data

	// Configuration snapshotted from package-level defaults at construction time.
	// Using struct fields instead of globals during computation eliminates data races
	// when defaults are updated between constructions.
	popWinSize     uint32 // snapshotted from PopWinSize
	threshold      uint32 // snapshotted from Threshold
	blockSize      int    // snapshotted from BlockSize
	entropyWinSize int    // snapshotted from EntropyWinSize
}

// readField reads a colon-terminated field from r and returns the value without the delimiter.
func readField(r *bufio.Reader) (string, error) {
	s, err := r.ReadString(':')
	if err != nil {
		return "", err
	}
	return s[:len(s)-1], nil
}

// readUint64Field reads a colon-terminated field from r and parses it as a decimal uint64.
func readUint64Field(r *bufio.Reader) (uint64, error) {
	s, err := readField(r)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}

// skipField reads and discards a colon-terminated field from r.
func skipField(r *bufio.Reader) error {
	_, err := r.ReadBytes(':')
	return err
}

// ParseSdbfFromString decodes a Sdbf from a digest string in sdbf wire format.
func ParseSdbfFromString(digest string) (Sdbf, error) {
	r := bufio.NewReader(strings.NewReader(digest))

	sd := &sdbf{}

	magic, err := readField(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}

	version, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if version > sdbfVersion {
		return nil, errors.New("unsupported sdbf version")
	}

	if err = skipField(r); err != nil { // namelen (always "1")
		return nil, fmt.Errorf("failed to read name length: %w", err)
	}
	if err = skipField(r); err != nil { // name (always "-")
		return nil, fmt.Errorf("failed to read name: %w", err)
	}

	if sd.origFileSize, err = readUint64Field(r); err != nil {
		return nil, fmt.Errorf("failed to read original file size: %w", err)
	}

	if err = skipField(r); err != nil { // hash algorithm (always "sha1")
		return nil, fmt.Errorf("failed to read hash algorithm: %w", err)
	}

	bfSize, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bloom filter size: %w", err)
	}

	if err = skipField(r); err != nil { // hash count
		return nil, fmt.Errorf("failed to read hash count: %w", err)
	}
	if err = skipField(r); err != nil { // bit mask
		return nil, fmt.Errorf("failed to read bit mask: %w", err)
	}

	maxElem, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read max elements: %w", err)
	}

	bfCount, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bloom filter count: %w", err)
	}

	switch magic {
	case magicStream:
		lastCount, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read last count: %w", err)
		}
		// Buffer is base64-encoded and terminated by '\n' (or EOF if no trailing newline).
		encodedBuffer, _ := r.ReadString('\n')
		if len(encodedBuffer) > 0 && encodedBuffer[len(encodedBuffer)-1] == '\n' {
			encodedBuffer = encodedBuffer[:len(encodedBuffer)-1] // strip newline
		}
		if sd.buffer, err = base64.StdEncoding.DecodeString(encodedBuffer); err != nil {
			return nil, fmt.Errorf("failed to decode buffer: %w", err)
		}
		sd.lastCount = uint32(lastCount)

	case magicDD:
		ddBlockSize, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read block size: %w", err)
		}
		sd.elemCounts = make([]uint16, bfCount)
		sd.buffer = make([]uint8, bfCount*bfSize)
		for i := uint64(0); i < bfCount; i++ {
			elemStr, err := readField(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read element count for filter %d: %w", i, err)
			}
			elem, err := strconv.ParseUint(elemStr, 16, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse element count for filter %d: %w", i, err)
			}
			sd.elemCounts[i] = uint16(elem)

			// Each block's base64 is delimited by ':' except the last, which ends at '\n' (or EOF).
			encodedBuffer, _ := r.ReadString(':')
			tmpBuffer, err := base64.StdEncoding.DecodeString(encodedBuffer[:len(encodedBuffer)-1])
			if err != nil {
				return nil, fmt.Errorf("failed to decode data for filter %d: %w", i, err)
			}
			copy(sd.buffer[i*bfSize:], tmpBuffer)
		}
		sd.ddBlockSize = uint32(ddBlockSize)

	default:
		return nil, fmt.Errorf("unrecognized sdbf magic %q", magic)
	}

	sd.bfSize = uint32(bfSize)
	sd.maxElem = uint32(maxElem)
	sd.bfCount = uint32(bfCount)
	sd.computeHamming()

	return sd, nil
}

// createSdbf creates and digests a sdbf from a byte buffer. Configuration is
// snapshotted from the package-level defaults at this point; subsequent changes
// to the defaults do not affect this digest.
//
// IMPORTANT: Do not add a default index bloom filter here. Adding one causes
// hash mismatches with the reference implementation.
func createSdbf(buffer []uint8, ddBlockSize uint32) (*sdbf, error) {
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
		sd.buffer = make([]uint8, ddBlockCnt*uint64(BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.generateBlockSdbf(buffer)
	}
	sd.computeHamming()

	return sd, nil
}

func (sd *sdbf) Size() uint64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

func (sd *sdbf) InputSize() uint64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.origFileSize
}

func (sd *sdbf) FilterCount() uint32 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.bfCount
}

func (sd *sdbf) Compare(other Sdbf) int {
	return sd.CompareSample(other, 0)
}

func (sd *sdbf) CompareSample(other Sdbf, sample uint32) int {
	o := other.(*sdbf)
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	o.mu.RLock()
	defer o.mu.RUnlock()
	return sdbfScore(sd, o, sample)
}

func (sd *sdbf) String() string {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	var sb strings.Builder
	isStream := sd.elemCounts == nil
	if isStream {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicStream, sdbfVersion))
	} else {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicDD, sdbfVersion))
	}
	sb.WriteString(fmt.Sprintf("1:-:%d:sha1:", sd.origFileSize))
	sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask))

	if isStream {
		sb.WriteString(fmt.Sprintf("%d:%d:%d:", sd.maxElem, sd.bfCount, sd.lastCount))
		qt, rem := sd.bfCount/6, sd.bfCount%6
		b64Block := uint64(6 * sd.bfSize)
		var pos uint64
		for i := uint32(0); i < qt; i++ {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%d:%d:%d", sd.maxElem, sd.bfCount, sd.ddBlockSize))
		for i := uint32(0); i < sd.bfCount; i++ {
			sb.WriteString(fmt.Sprintf(":%02x:", sd.elemCounts[i]))
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[i*sd.bfSize : i*sd.bfSize+sd.bfSize]))
		}
	}
	sb.WriteByte('\n')

	return sb.String()
}

// elemCount returns the element count for the filter at index.
// The caller must hold at least a read lock.
func (sd *sdbf) elemCount(index uint32) uint32 {
	if sd.elemCounts == nil {
		if index < sd.bfCount-1 {
			return sd.maxElem
		}
		return sd.lastCount
	}
	return uint32(sd.elemCounts[index])
}

// computeHamming precomputes the hamming weight for each bloom filter in the buffer.
func (sd *sdbf) computeHamming() {
	sd.hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		var h uint16
		for _, b := range sd.buffer[sd.bfSize*i : sd.bfSize*(i+1)] {
			h += uint16(bits.OnesCount8(b))
		}
		sd.hamming[i] = h
	}
}
