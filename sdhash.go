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

// errBoundExceeded is returned by readBoundedString when delim is not found
// within maxLen bytes.
var errBoundExceeded = errors.New("read exceeded expected length without finding delimiter")

// readBoundedString reads from r, one byte at a time, until delim is found
// or maxLen bytes have been consumed, whichever comes first. It mirrors
// bufio.Reader.ReadString but caps the number of bytes it will ever buffer.
//
// This intentionally avoids wrapping r in a second bufio.Reader (e.g. via
// io.LimitReader): doing so lets the inner reader pre-fetch bytes from r
// into its own buffer that are never consumed if the delimiter is found
// early, and those bytes are silently lost on the next call. Reading
// directly from r one byte at a time keeps a single buffering layer, so
// nothing is dropped between calls, while still bounding worst-case memory
// use to maxLen regardless of what the underlying stream sends.
func readBoundedString(r *bufio.Reader, delim byte, maxLen int) (string, error) {
	var sb strings.Builder
	for i := 0; i < maxLen; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		sb.WriteByte(b)
		if b == delim {
			return sb.String(), nil
		}
	}
	return sb.String(), errBoundExceeded
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
		// bfCount and bfSize are already validated against maxBfAlloc above.
		// Cap this read at the expected encoded length, plus a couple of
		// bytes of slack for the line terminator. This avoids letting
		// ReadString buffer an attacker-controlled line of unbounded length
		// before any size check runs.
		expectedEncodedLen := base64.StdEncoding.EncodedLen(int(bfCount * bfSize))
		encodedBuffer, _ := readBoundedString(r, '\n', expectedEncodedLen+2)
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
		expectedLen := base64.StdEncoding.EncodedLen(bfSize)
		encodedBuf := make([]byte, expectedLen)
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

			// Each block's base64 payload is a fixed, known length (derived
			// from bfSize, not attacker data), so read exactly that many
			// bytes instead of scanning for a delimiter. This removes an
			// ambiguity the previous delimiter-search had for the last
			// block specifically: it has no trailing ':', so a search for
			// one had to run to the end of its bound regardless, silently
			// consuming bytes belonging to whatever followed — including a
			// second digest immediately concatenated in the same stream.
			if _, err := io.ReadFull(r, encodedBuf); err != nil {
				return nil, fmt.Errorf("failed to read encoded data for filter %d: %w", i, err)
			}

			if i < bfCount-1 {
				// Every block but the last is delimited by a single ':'.
				b, err := r.ReadByte()
				if err != nil {
					return nil, fmt.Errorf("failed to read delimiter after filter %d: %w", i, err)
				}
				if b != ':' {
					return nil, fmt.Errorf("expected ':' delimiter after filter %d, got %q", i, b)
				}
			} else {
				// The last block ends at '\r\n', '\n', or EOF. Consume
				// exactly that much and no more: anything else found here
				// belongs to whatever follows (e.g. a second,
				// immediately-concatenated digest) and must be left unread
				// for the next parse, not swallowed.
				b, err := r.ReadByte()
				switch {
				case err != nil:
					// EOF is a valid terminator for the last block.
				case b == '\n':
					// Bare '\n' terminator, already fully consumed.
				case b == '\r':
					b2, err2 := r.ReadByte()
					if err2 != nil || b2 != '\n' {
						return nil, fmt.Errorf("malformed line ending after filter %d", i)
					}
				default:
					// UnreadByte immediately follows a successful ReadByte,
					// which bufio.Reader guarantees always succeeds in that
					// position — there is always at least one byte to give
					// back at this point.
					_ = r.UnreadByte()
				}
			}

			decoded, err := base64.StdEncoding.DecodeString(string(encodedBuf))
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
