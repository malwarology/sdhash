package sdhash

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// Digest represents the similarity digest of a file or byte buffer. Two Digest values
// can be compared to produce a score indicating how similar their source data is.
//
// Digest values are immutable after construction. Every method is safe for
// concurrent use by multiple goroutines because no field is ever written
// after the factory returns.
type Digest interface {

	// FilterSize returns the total byte size of the bloom filter data within this Digest.
	FilterSize() uint64

	// InputSize returns the size of the original data this Digest was generated from.
	InputSize() uint64

	// FilterCount returns the number of bloom filters in this Digest.
	FilterCount() uint32

	// Similarity returns a similarity score in [0, 100] between this Digest and other,
	// and a boolean indicating whether the comparison was meaningful. Returns
	// (0, false) if other is nil, was not produced by this package, or if both
	// digests are degenerate and all filters fall below the minimum element
	// threshold.
	Similarity(other Digest) (int, bool)

	// String returns the digest encoded as a string in the sdbf wire format.
	String() string

	// FeatureDensity returns the ratio of total unique features inserted across
	// all bloom filters to the original input size. A low value indicates the
	// digest is degenerate — the input was too repetitive, low-entropy, or small
	// to produce enough features for a meaningful similarity comparison. Callers
	// should check this value and treat digests below a corpus-appropriate
	// threshold as unreliable.
	FeatureDensity() float64
}

type sdbf struct {
	hamming      []uint16       // hamming weight for each bloom filter; always set after construction
	buffer       []byte         // concatenated bloom filter data
	maxElem      uint32         // max elements per filter
	bigFilters   []*bloomFilter // large deduplication filters used during stream-mode digesting
	bfCount      uint32         // number of bloom filters
	bfSize       uint32         // bloom filter size in bytes
	lastCount    uint32         // element count in the final filter (stream mode only)
	elemCounts   []uint16       // per-filter element counts (block mode only)
	ddBlockSize  uint32         // block size in block mode
	origFileSize uint64         // size of the original input data

	// Algorithm parameters initialized from package constants.
	popWinSize     uint32
	threshold      uint32
	blockSize      int
	testFaultHook  func() // test-only: injects a fault in generateChunkRanks to exercise goroutine panic recovery; nil in production
	entropyWinSize int
}

func (sd *sdbf) FilterSize() uint64 {
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

func (sd *sdbf) InputSize() uint64 {
	return sd.origFileSize
}

func (sd *sdbf) FilterCount() uint32 {
	return sd.bfCount
}

func (sd *sdbf) FeatureDensity() float64 {
	if sd.origFileSize == 0 {
		return 0
	}
	var totalElements uint64
	if sd.elemCounts == nil {
		// Stream mode: all filters except the last hold maxElem elements.
		if sd.bfCount > 0 {
			totalElements = uint64(sd.bfCount-1)*uint64(sd.maxElem) + uint64(sd.lastCount)
		}
	} else {
		// DD (block) mode: each filter tracks its own count.
		for i := range sd.bfCount {
			totalElements += uint64(sd.elemCounts[i])
		}
	}
	return float64(totalElements) / float64(sd.origFileSize)
}

func (sd *sdbf) Similarity(other Digest) (int, bool) {
	if other == nil {
		return 0, false
	}
	o, ok := other.(*sdbf)
	if !ok {
		return 0, false
	}
	result := sdbfScore(sd, o)
	if result < 0 {
		return 0, false
	}
	return result, true
}

func (sd *sdbf) String() string {
	var sb strings.Builder
	isStream := sd.elemCounts == nil
	if isStream {
		_, _ = fmt.Fprintf(&sb, "%s:%02d:", magicStream, sdbfVersion)
	} else {
		_, _ = fmt.Fprintf(&sb, "%s:%02d:", magicDD, sdbfVersion)
	}
	_, _ = fmt.Fprintf(&sb, "1:-:%d:sha1:", sd.origFileSize)
	_, _ = fmt.Fprintf(&sb, "%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask)

	if isStream {
		_, _ = fmt.Fprintf(&sb, "%d:%d:%d:", sd.maxElem, sd.bfCount, sd.lastCount)
		qt, rem := sd.bfCount/6, sd.bfCount%6
		b64Block := uint64(6 * sd.bfSize)
		var pos uint64
		for range qt {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		_, _ = fmt.Fprintf(&sb, "%d:%d:%d", sd.maxElem, sd.bfCount, sd.ddBlockSize)
		bfSize := uint64(sd.bfSize)
		for i := range sd.bfCount {
			_, _ = fmt.Fprintf(&sb, ":%02x:", sd.elemCounts[i])
			start := uint64(i) * bfSize
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[start : start+bfSize]))
		}
	}
	sb.WriteByte('\n')

	return sb.String()
}

// elemCount returns the element count for the filter at index.
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
	bfSize := uint64(sd.bfSize)
	for i := range sd.bfCount {
		start := bfSize * uint64(i)
		var h uint16
		for _, b := range sd.buffer[start : start+bfSize] {
			h += uint16(bits.OnesCount8(b))
		}
		sd.hamming[i] = h
	}
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

// ParseReader decodes a single Digest from a reader in sdbf wire format.
// The reader is consumed through the end of the digest, including the trailing
// newline if present. For files containing multiple digests, call this function
// repeatedly until io.EOF is encountered.
func ParseReader(reader io.Reader) (Digest, error) {
	r, ok := reader.(*bufio.Reader)
	if !ok {
		r = bufio.NewReader(reader)
	}

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
		return nil, fmt.Errorf("unsupported sdbf version %d (maximum supported: %d)", version, sdbfVersion)
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

	parsedBfSize, err := readUint64Field(r)
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

	const maxBfAlloc = 256 * 1024 * 1024
	if parsedBfSize == 0 {
		return nil, errors.New("bloom filter size must be greater than zero")
	}
	if parsedBfSize != bfSize {
		return nil, fmt.Errorf("unsupported bloom filter size %d (only %d is supported)", parsedBfSize, bfSize)
	}
	if bfCount > maxBfAlloc/parsedBfSize {
		return nil, fmt.Errorf("bloom filter allocation too large: %d filters × %d bytes exceeds %d byte limit", bfCount, parsedBfSize, maxBfAlloc)
	}
	if maxElem == 0 || maxElem > maxElemDd {
		return nil, fmt.Errorf("maxElem %d is invalid (must be between 1 and %d)", maxElem, maxElemDd)
	}

	switch magic {
	case magicStream:
		lastCount, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read last count: %w", err)
		}
		// Buffer is base64-encoded and terminated by '\r\n', '\n', or EOF.
		encodedBuffer, _ := r.ReadString('\n')
		encodedBuffer = strings.TrimRight(encodedBuffer, "\r\n")
		if sd.buffer, err = base64.StdEncoding.DecodeString(encodedBuffer); err != nil {
			return nil, fmt.Errorf("failed to decode buffer: %w", err)
		}
		sd.lastCount = uint32(lastCount)
		if uint64(len(sd.buffer)) != bfCount*bfSize {
			return nil, fmt.Errorf("stream buffer length %d does not match expected %d (bfCount=%d × bfSize=%d)", len(sd.buffer), bfCount*bfSize, bfCount, bfSize)
		}
		if lastCount > maxElem {
			return nil, fmt.Errorf("lastCount %d exceeds maxElem %d", lastCount, maxElem)
		}

	case magicDD:
		ddBlockSize, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read block size: %w", err)
		}
		if ddBlockSize > math.MaxUint32 {
			return nil, fmt.Errorf("ddBlockSize %d exceeds maximum uint32 value", ddBlockSize)
		}
		sd.elemCounts = make([]uint16, bfCount)
		sd.buffer = make([]byte, bfCount*bfSize)
		for i := range bfCount {
			elemStr, err := readField(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read element count for filter %d: %w", i, err)
			}
			elem, err := strconv.ParseUint(elemStr, 16, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse element count for filter %d: %w", i, err)
			}
			sd.elemCounts[i] = uint16(elem)
			if elem > maxElem {
				return nil, fmt.Errorf("element count %d for filter %d exceeds maxElem %d", elem, i, maxElem)
			}

			// Each block's base64 is delimited by ':' except the last, which ends at '\r\n', '\n', or EOF.
			encodedBuffer, readErr := r.ReadString(':')
			var encodedStr string
			if readErr != nil {
				encodedStr = strings.TrimRight(encodedBuffer, "\r\n")
			} else {
				encodedStr = encodedBuffer[:len(encodedBuffer)-1]
			}

			expectedLen := base64.StdEncoding.EncodedLen(bfSize)
			if len(encodedStr) != expectedLen {
				return nil, fmt.Errorf("encoded block %d length %d does not match expected %d", i, len(encodedStr), expectedLen)
			}

			decoded, err := base64.StdEncoding.DecodeString(encodedStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode data for filter %d: %w", i, err)
			}
			if len(decoded) != bfSize {
				return nil, fmt.Errorf("decoded block %d length %d does not match bfSize %d", i, len(decoded), bfSize)
			}
			copy(sd.buffer[i*bfSize:], decoded)
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

// Parse decodes a Digest from a digest string in sdbf wire format.
func Parse(digest string) (Digest, error) {
	return ParseReader(strings.NewReader(digest))
}
