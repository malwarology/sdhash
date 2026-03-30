package sdhash

import "math"

var entropy64Int [65]uint64

func init() {
	// Precompute scaled entropy contributions for each possible byte-frequency count.
	for i := 1; i <= 64; i++ {
		p := float64(i) / 64
		entropy64Int[i] = uint64((-p * math.Log2(p) / 6) * entropyScale)
	}
}

// entropy64InitInt performs a full entropy computation for a 64-byte buffer.
func entropy64InitInt(buffer []byte, ascii []byte) uint64 {
	clear(ascii)
	for i := 0; i < 64; i++ {
		ascii[buffer[i]]++
	}
	var entropy uint64
	for i := 0; i < 256; i++ {
		if ascii[i] > 0 {
			entropy += entropy64Int[ascii[i]]
		}
	}
	return entropy
}

// entropy64IncInt performs an incremental (rolling) entropy update for a 64-byte window.
func entropy64IncInt(prevEntropy uint64, buffer []byte, ascii []byte) uint64 {
	if buffer[0] == buffer[64] {
		return prevEntropy
	}

	oldCharCnt := ascii[buffer[0]]
	newCharCnt := ascii[buffer[64]]

	ascii[buffer[0]]--
	ascii[buffer[64]]++

	if oldCharCnt == newCharCnt+1 {
		return prevEntropy
	}

	oldDiff := int64(entropy64Int[oldCharCnt]) - int64(entropy64Int[oldCharCnt-1])
	newDiff := int64(entropy64Int[newCharCnt+1]) - int64(entropy64Int[newCharCnt])

	entropy := int64(prevEntropy) - oldDiff + newDiff
	if entropy < 0 {
		entropy = 0
	} else if entropy > entropyScale {
		entropy = entropyScale
	}

	return uint64(entropy)
}
