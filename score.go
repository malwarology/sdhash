package sdhash

import "math"

// sdbfScore calculates the similarity score (0–100) between two sdbf digests.
// Both digests must have their hamming weights pre-computed (guaranteed after construction).
// Returns -1 if the comparison cannot be performed (no filters, or no filter pair
// produced a valid comparison).
//
//goland:noinspection DuplicatedCode
func sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf) int {
	bfCount1 := sdbf1.bfCount

	// Always iterate over the smaller digest. This minimizes the number of
	// sdbfMaxScore calls while still finding the best match for every filter
	// in the smaller digest against the full larger digest.
	// When bfCount is equal, break the tie by comparing the element count of
	// the last bloom filter; the digest with the larger last-filter element
	// count becomes the target. The bfCount1 > 0 guard prevents an underflow
	// on the elemCount(bfCount1-1) call when both digests have zero filters.
	// (The C++ reference has a third tiebreaker on strcmp(hashname) which is
	// omitted here because Go digests do not carry names.)
	if bfCount1 > sdbf2.bfCount ||
		(bfCount1 == sdbf2.bfCount && bfCount1 > 0 &&
			sdbf1.elemCount(bfCount1-1) > sdbf2.elemCount(sdbf2.bfCount-1)) {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 == 0 {
		return -1
	}

	var scoreSum float64
	var sparseCount uint32   // source filter too sparse; sdbfMaxScore returned 0
	var noTargetCount uint32 // no scoreable target filter; sdbfMaxScore returned -1
	for i := uint32(0); i < bfCount1; i++ {
		s := sdbfMaxScore(sdbf1, i, sdbf2)
		if s < 0 {
			// No target filter had enough elements to compare against.
			// Exclude this filter from both the sum and the denominator.
			noTargetCount++
			continue
		}
		scoreSum += s
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	// Filters that produced no valid comparison are excluded unconditionally.
	// Sparse source filters are excluded only when there is more than one filter,
	// preserving the original behavior for single-filter digests.
	denominator := bfCount1 - noTargetCount
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	if denominator == 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScore calculates the maximum match of a single reference filter against all target filters.
// Returns 0 if the reference filter has too few elements for a valid comparison, -1 if no target
// filter had enough elements to score against, or a value in [0.0, 1.0] otherwise.
func sdbfMaxScore(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
	var maxScore float64 = -1
	bfSize := refSdbf.bfSize

	s1 := refSdbf.elemCount(refIndex)
	if s1 < minElemCount {
		return 0
	}
	bf1 := refSdbf.buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.buffer[i*bfSize:]
		s2 := targetSdbf.elemCount(i)
		if s2 < minElemCount {
			continue
		}
		e2Cnt := targetSdbf.hamming[i]
		maxEst := min(e1Cnt, e2Cnt)
		cutOff := cutoffBySum[s1+s2]
		var score float64
		match := andPopcount(bf1, bf2)
		if match > cutOff {
			score = float64(match-cutOff) / float64(uint32(maxEst)-cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}
