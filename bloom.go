package sdhash

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type bloomFilter struct {
	buffer    []byte // bloom filter data
	bitMask   uint64 // bit mask derived from filter size
	maxElem   uint64 // maximum number of elements
	hashCount uint16 // number of hash functions (k)
}

func newBloomFilter(size uint64, hashCount uint16, maxElem uint64) (*bloomFilter, error) {
	bf := &bloomFilter{
		hashCount: hashCount,
		maxElem:   maxElem,
	}

	// Size must be a power of 2 and at least 64.
	if size >= 64 && (size&(size-1)) == 0 {
		bf.bitMask = size*8 - 1
	} else {
		return nil, errors.New("bloom filter size must be a power of 2 and at least 64 bytes")
	}

	bf.buffer = make([]byte, size)

	return bf, nil
}

// mustNewBloomFilter is like newBloomFilter but panics on error.
// Use it only when the size argument is a compile-time constant known to be
// a valid power of two ≥ 64 (e.g. bigFilter = 16384), making the error path
// unreachable.
func mustNewBloomFilter(size uint64, hashCount uint16, maxElem uint64) *bloomFilter {
	bf, err := newBloomFilter(size, hashCount, maxElem)
	if err != nil {
		panic(err)
	}
	return bf
}

// insertSha1 inserts a SHA1 hash into the bloom filter.
// Returns true if the element was new (i.e. at least one bit was not already set).
func (bf *bloomFilter) insertSha1(sha1 []uint32) bool {
	var pos, k uint32
	var bitCount uint16
	for i := uint16(0); i < bf.hashCount; i++ {
		pos = sha1[i] & uint32(bf.bitMask)
		k = pos >> 3
		if (bf.buffer[k] & bitPositions[pos&0x7]) != 0 {
			bitCount++
		} else {
			bf.buffer[k] |= bitPositions[pos&0x7]
		}
	}
	return bitCount < bf.hashCount
}

// bfInsertSha1 inserts a SHA1 hash into a raw bloom filter buffer and returns the number of newly set bits.
func bfInsertSha1(bf []byte, sha1Hash [5]uint32) uint32 {
	var insertCnt uint32
	for i := range sha1Hash {
		insert := sha1Hash[i] & defaultMask
		k := insert >> 3
		if bf[k]&bitPositions[insert&0x7] == 0 {
			insertCnt++
		}
		bf[k] |= bitPositions[insert&0x7]
	}
	return insertCnt
}

// andPopcount returns the number of bits set in the AND of two 256-byte bloom
// filters. The function is the innermost hot loop of the Compare path and is
// implemented using 64-bit-wide popcount.
//
// OPTIMIZATION: The previous implementation iterated 256 times calling
// bits.OnesCount8, which is a 256-byte lookup table in the Go standard
// library (see math/bits/bits.go: OnesCount8 returns int(pop8tab[x])).
// bits.OnesCount64 on amd64 (with POPCNT) and arm64 is a compiler intrinsic
// that maps to a single hardware population-count instruction. By reading
// 8 bytes at a time via binary.LittleEndian.Uint64 and calling OnesCount64,
// we replace 256 table lookups with 32 hardware popcount instructions.
// The loop is fully unrolled by the compiler since bfSize is constant.
//
// Endianness is irrelevant to the result: popcount counts bits regardless
// of the order in which bytes are packed into the uint64. LittleEndian is
// used because on both amd64 and arm64 it compiles to a single unaligned
// load (MOV / LDR) with no byte-reordering, which is the fastest path.
func andPopcount(bf1, bf2 []byte) uint32 {
	// bfSize is a package-level constant of 256 bytes = 32 uint64 words.
	// The compiler unrolls the bounds-checked slice accesses because the
	// loop bound and slice lengths are both effectively constant here.
	_ = bf1[255] // early bounds check hint: one panic site instead of many
	_ = bf2[255]
	var count int
	for i := 0; i < 256; i += 8 {
		a := binary.LittleEndian.Uint64(bf1[i:])
		b := binary.LittleEndian.Uint64(bf2[i:])
		count += bits.OnesCount64(a & b)
	}
	return uint32(count)
}

// andPopcountCut computes the AND-popcount of two 256-byte bloom filters
// with staged early termination. It processes the filters in four stages
// (32, 32, 64, 128 bytes), extrapolating the partial count after each
// stage. If the extrapolated count plus slack falls below cutOff, it
// returns 0 immediately without computing the remainder.
//
// This mirrors the C++ reference's bf_bitcount_cut_256 function, which
// uses this heuristic as a performance optimization to avoid full popcount
// on filter pairs that are unlikely to exceed the similarity cutoff.
//
// This function is used only by CompareRef for C++ reference compatibility.
func andPopcountCut(bf1, bf2 []byte, cutOff uint32, slack int32) uint32 {
	_ = bf1[255]
	_ = bf2[255]

	var count uint32

	// Stage 1: bytes 0–31 (1/8 of filter).
	for i := 0; i < 32; i += 8 {
		a := binary.LittleEndian.Uint64(bf1[i:])
		b := binary.LittleEndian.Uint64(bf2[i:])
		count += uint32(bits.OnesCount64(a & b))
	}
	if cutOff > 0 && int32(8*count)+slack < int32(cutOff) {
		return 0
	}

	// Stage 2: bytes 32–63 (now have 1/4 of filter).
	for i := 32; i < 64; i += 8 {
		a := binary.LittleEndian.Uint64(bf1[i:])
		b := binary.LittleEndian.Uint64(bf2[i:])
		count += uint32(bits.OnesCount64(a & b))
	}
	if cutOff > 0 && int32(4*count)+slack < int32(cutOff) {
		return 0
	}

	// Stage 3: bytes 64–127 (now have 1/2 of filter).
	for i := 64; i < 128; i += 8 {
		a := binary.LittleEndian.Uint64(bf1[i:])
		b := binary.LittleEndian.Uint64(bf2[i:])
		count += uint32(bits.OnesCount64(a & b))
	}
	if cutOff > 0 && int32(2*count)+slack < int32(cutOff) {
		return 0
	}

	// Stage 4: bytes 128–255 (full filter).
	for i := 128; i < 256; i += 8 {
		a := binary.LittleEndian.Uint64(bf1[i:])
		b := binary.LittleEndian.Uint64(bf2[i:])
		count += uint32(bits.OnesCount64(a & b))
	}

	return count
}
