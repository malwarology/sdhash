// Package-internal file: contains the C++-reference-compatible bloom filter
// popcount primitive. The andPopcountCut function implements the staged
// early-exit heuristic used by the C++ sdhash reference, called only from
// the reference scoring path (sdbfMaxScoreRef). This file is part of the
// C++ reference-compatibility surface, frozen at v0.6.0 and removed in
// v1.0.0.
//
// Modifications to this file warrant extra review.

package sdhash

import (
	"encoding/binary"
	"math/bits"
)

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
