package sdhash

import (
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

// bfSha1Insert inserts a SHA1 hash into a raw bloom filter buffer and returns the number of newly set bits.
func bfSha1Insert(bf []byte, sha1Hash [5]uint32) uint32 {
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

// andPopcount returns the number of bits set in the AND of two 256-byte bloom filters.
func andPopcount(bf1, bf2 []byte) uint32 {
	var count uint32
	for i := 0; i < 256; i++ {
		count += uint32(bits.OnesCount8(bf1[i] & bf2[i]))
	}
	return count
}
