package sdhash

import "math"

var entropy64Int [65]uint64

// entropy64Delta[k] holds int64(entropy64Int[k]) - int64(entropy64Int[k-1]),
// the adjacent difference used by entropy64Update. Because entropy64Int is a
// fixed table, this difference is a constant function of k; precomputing it
// folds two table loads and a subtract in the hot path down to one load.
// Indices used: [1,64] (oldCharCnt) and [1,64] (newCharCnt+1).
var entropy64Delta [65]int64

func init() {
	// Precompute scaled entropy contributions for each possible byte-frequency count.
	for i := 1; i <= 64; i++ {
		p := float64(i) / 64
		entropy64Int[i] = uint64((-p * math.Log2(p) / 6) * entropyScale)
	}
	// Precompute adjacent differences (depends on entropy64Int above).
	for k := 1; k <= 64; k++ {
		entropy64Delta[k] = int64(entropy64Int[k]) - int64(entropy64Int[k-1])
	}
}

// entropy64Compute performs a full entropy computation for a 64-byte buffer.
func entropy64Compute(buffer []byte, ascii []byte) uint64 {
	clear(ascii)
	for i := range 64 {
		ascii[buffer[i]]++
	}
	var entropy uint64
	for i := range 256 {
		if ascii[i] > 0 {
			entropy += entropy64Int[ascii[i]]
		}
	}
	return entropy
}

// entropy64Update performs an incremental (rolling) entropy update for a 64-byte window.
func entropy64Update(prevEntropy uint64, buffer []byte, ascii []byte) uint64 {
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

	oldDiff := entropy64Delta[oldCharCnt]
	newDiff := entropy64Delta[newCharCnt+1]

	entropy := int64(prevEntropy) - oldDiff + newDiff
	if entropy < 0 {
		entropy = 0
	} else if entropy > entropyScale {
		entropy = entropyScale
	}

	return uint64(entropy)
}
