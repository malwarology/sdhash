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

// Sdbf represents the similarity digest of a file or byte buffer. Two Sdbf values
// can be compared to produce a score indicating how similar their source data is.
//
// Sdbf values are immutable after construction. Every method is safe for
// concurrent use by multiple goroutines because no field is ever written
// after the factory returns.
type Sdbf interface {

	// Size returns the total byte size of the bloom filter data within this Sdbf.
	Size() uint64

	// InputSize returns the size of the original data this Sdbf was generated from.
	InputSize() uint64

	// FilterCount returns the number of bloom filters in this Sdbf.
	FilterCount() uint32

	// Compare returns a similarity score in [0, 100] between this Sdbf and other,
	// and a boolean indicating whether the comparison was meaningful. Returns
	// (0, false) if other is nil, was not produced by this package, or if both
	// digests are degenerate and all filters fall below the minimum element
	// threshold.
	Compare(other Sdbf) (int, bool)

	// CompareRef returns the similarity score between this Sdbf and other
	// using C++-reference-compatible semantics. The returned int is in
	// [0, 100] for a valid comparison, or -1 if the comparison is
	// degenerate (all filters below the minimum element threshold).
	//
	// This method exists during the reference correctness phase of the
	// port to support external test harnesses that compare the Go
	// library's output byte-for-byte against the C++ reference via CSV
	// diffing. Its return shape matches the C++ compare() method exactly.
	//
	// Deprecated: CompareRef will be removed when C++ reference
	// compatibility is dropped at 1.0.0. New code should use Compare,
	// which returns (int, bool) in the idiomatic Go form.
	CompareRef(other Sdbf) int

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
	entropyWinSize int
}

func (sd *sdbf) Size() uint64 {
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
		for i := uint32(0); i < sd.bfCount; i++ {
			totalElements += uint64(sd.elemCounts[i])
		}
	}
	return float64(totalElements) / float64(sd.origFileSize)
}

func (sd *sdbf) Compare(other Sdbf) (int, bool) {
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

func (sd *sdbf) CompareRef(other Sdbf) int {
	if other == nil {
		return -1
	}
	o, ok := other.(*sdbf)
	if !ok {
		return -1
	}
	return sdbfScoreRef(sd, o)
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
		for i := uint32(0); i < qt; i++ {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		_, _ = fmt.Fprintf(&sb, "%d:%d:%d", sd.maxElem, sd.bfCount, sd.ddBlockSize)
		for i := uint32(0); i < sd.bfCount; i++ {
			_, _ = fmt.Fprintf(&sb, ":%02x:", sd.elemCounts[i])
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[i*sd.bfSize : i*sd.bfSize+sd.bfSize]))
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
	for i := uint32(0); i < sd.bfCount; i++ {
		var h uint16
		for _, b := range sd.buffer[sd.bfSize*i : sd.bfSize*(i+1)] {
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

// ParseSdbfFromReader decodes a single Sdbf from a reader in sdbf wire format.
// The reader is consumed through the end of the digest, including the trailing
// newline if present. For files containing multiple digests, call this function
// repeatedly until io.EOF is encountered.
func ParseSdbfFromReader(reader io.Reader) (Sdbf, error) {
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

// ParseSdbfFromString decodes a Sdbf from a digest string in sdbf wire format.
func ParseSdbfFromString(digest string) (Sdbf, error) {
	return ParseSdbfFromReader(strings.NewReader(digest))
}
