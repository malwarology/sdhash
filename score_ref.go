// Package-internal file: contains the C++-reference-compatible scoring path.
// These functions reproduce the C++ sdhash reference implementation's
// scoring behavior exactly, for use during the Go port's reference
// correctness phase. They are scheduled for removal at 1.0.0 when C++
// reference compatibility is dropped.
//
// Modifications to this file warrant extra review. The byte-identity
// of CompareRef's output against the C++ reference across millions of
// pairs depends on this code not drifting.

package sdhash

import "math"

const shortCircuitSlack = 48

// sdbfScoreRef calculates the similarity score using C++ reference-compatible
// semantics. It differs from sdbfScore in two ways:
//
// C++ accumulation: score_sum starts at -1. On each iteration, if score_sum
// is negative it is replaced by max_score (assignment); otherwise max_score
// is added. This means a non-negative max_score resets any accumulated
// negative, matching the C++ behavior where the first non-negative result
// initializes the sum.
//
// C++ denominator-zero: when denominator is 0, score_sum is set to -1
// (not decremented), matching the C++ assignment.
//goland:noinspection DuplicatedCode
func sdbfScoreRef(sdbf1 *sdbf, sdbf2 *sdbf) int {
	bfCount1 := sdbf1.bfCount

	if bfCount1 > sdbf2.bfCount ||
		(bfCount1 == sdbf2.bfCount && bfCount1 > 0 &&
			sdbf1.elemCount(bfCount1-1) > sdbf2.elemCount(sdbf2.bfCount-1)) {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 == 0 {
		return -1
	}

	// C++ accumulation: score_sum starts at -1 and uses conditional
	// assignment on the first non-negative max_score.
	var scoreSum float64 = -1
	var sparseCount uint32
	for i := uint32(0); i < bfCount1; i++ {
		maxScore := sdbfMaxScoreRef(sdbf1, i, sdbf2)
		if scoreSum < 0 {
			scoreSum = maxScore
		} else {
			scoreSum += maxScore
		}
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	denominator := bfCount1
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	// C++ sets score_sum to -1 when denominator is 0.
	if denominator == 0 {
		scoreSum = -1
	}

	if scoreSum < 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScoreRef is the C++ reference-compatible version of sdbfMaxScore.
// It uses a two-pass match: andPopcountCut with early-exit heuristics
// screens filter pairs first, and only pairs that survive proceed to a
// full exact popcount via andPopcount. This replicates the C++ reference's
// bf_bitcount_cut_256 behavior with slack=48.
func sdbfMaxScoreRef(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
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

		// C++ two-pass match: short-circuit screening then exact count.
		var match uint32
		if andPopcountCut(bf1, bf2, cutOff, shortCircuitSlack) > 0 {
			match = andPopcount(bf1, bf2)
		}

		var score float64
		if match > cutOff {
			score = float64(match-cutOff) / float64(uint32(maxEst)-cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}
