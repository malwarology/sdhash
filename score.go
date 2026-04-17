package sdhash

import "math"

// sdbfScore calculates the similarity score (0–100) between two sdbf digests.
// Both digests must have their hamming weights pre-computed (guaranteed after construction).
func sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf) int {
	bfCount1 := sdbf1.bfCount

	// Always iterate over the smaller digest. This minimizes the number of
	// sdbfMaxScore calls while still finding the best match for every filter
	// in the smaller digest against the full larger digest.
	if bfCount1 > sdbf2.bfCount {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 == 0 {
		return -1
	}

	var scoreSum float64
	var sparseCount uint32
	for i := uint32(0); i < bfCount1; i++ {
		scoreSum += sdbfMaxScore(sdbf1, i, sdbf2)
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	denominator := bfCount1
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	if denominator == 0 {
		scoreSum--
	}

	if scoreSum < 0 {
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
		cutOff := cutoffs256[4096/(s1+s2)]
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
