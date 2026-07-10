// This file provides package-level accessors into the private state of
// the sdbf type for use by the reference-correctness test harness. It is
// part of the debug surface, frozen at v0.6.0 and removed in v1.0.0.
//
// None of the functions in this file are part of the library's public
// API. Do not depend on them from outside the test methodology.

package sdhash

// DebugRevertAdditiveAccumulation makes CompareDebug use the C++-faithful
// conditional-first-assignment accumulation pattern instead of the modern
// additive accumulation from zero when true.
// Additive accumulation is the correct algorithm; the C++ pattern
// was a defect. Used for demonstrations.
//
// Default: false.
var DebugRevertAdditiveAccumulation bool

// DebugRevertExactPopcount makes CompareDebug use the C++-faithful staged
// early-exit popcount heuristic (andPopcountCut screening before exact
// andPopcount) instead of the modern exact popcount directly when true. Exact popcount is the correct
// algorithm; the C++ heuristic traded correctness for performance.
// Used for demonstrations.
//
// Default: false.
var DebugRevertExactPopcount bool

// DebugRevertChunkScoresDoubleCount makes NewDebug construct digests using the
// C++-faithful two-block chunk-score feature selection instead of the modern
// one-increment-per-window selection when true. The C++ two-block algorithm
// double-counts positions in equal-rank runs; the modern algorithm is the
// correct one. Unlike the other toggles this affects hashing (digest
// construction), not scoring, so it changes which features a digest contains.
//
// Default: false.
var DebugRevertChunkScoresDoubleCount bool

// MaxElem returns the per-filter element saturation cap configured for
// this digest. This is 160 for stream-mode digests and 192 for DD-mode
// digests.
func MaxElem(s Sdbf) uint32 {
	return s.(*sdbf).maxElem
}

// DDBlockSize returns the DD-mode block size in bytes, or 0 for
// stream-mode digests.
func DDBlockSize(s Sdbf) uint32 {
	return s.(*sdbf).ddBlockSize
}

// LastCount returns the element count of the final bloom filter. In
// stream mode this is the tail filter's count; in DD mode it is
// always 0.
func LastCount(s Sdbf) uint32 {
	return s.(*sdbf).lastCount
}

// ElemCount returns the element count of the bloom filter at the given
// index. Callers must ensure 0 <= index < FilterCount(s).
func ElemCount(s Sdbf, index uint32) uint32 {
	return s.(*sdbf).elemCount(index)
}

// Hamming returns the Hamming weight (number of set bits) of the bloom
// filter at the given index. Callers must ensure
// 0 <= index < FilterCount(s).
func Hamming(s Sdbf, index uint32) uint16 {
	return s.(*sdbf).hamming[index]
}

// TotalElements returns the sum of element counts across all bloom
// filters in the digest. This is the numerator of FeatureDensity
// (FeatureDensity returns TotalElements / InputSize).
func TotalElements(s Sdbf) uint64 {
	sd := s.(*sdbf)
	var total uint64
	for i := uint32(0); i < sd.bfCount; i++ {
		total += uint64(sd.elemCount(i))
	}
	return total
}
