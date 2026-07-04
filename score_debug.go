// Package-internal file: contains the toggle-gated scoring variant used
// for handoff investigations and demonstrations. CompareDebug and its
// helpers exist to support empirical A/B comparison of individual
// scoring fixes. Not part of the library's public scoring API.
//
// Scheduled for removal together with the other debug machinery when
// the reference correctness phase completes.
//
// Modifications to this file are expected during the investigation.
// Unlike score_ref.go, this file is not frozen.

package sdhash

import (
	"math"
)

// sdbfScoreDebug calculates the similarity score between two sdbf digests
// using a toggle-gated variant of the modern sdbfScore algorithm. With all
// toggles at their default false values, it produces output identical to
// sdbfScore. Individual toggles revert specific fixes.
//goland:noinspection DuplicatedCode
func sdbfScoreDebug(sdbf1 *sdbf, sdbf2 *sdbf) int {
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

	var sparseCount uint32

	if DebugRevertAdditiveAccumulation {
		// C++-faithful: conditional-first-assignment from -1, no noTargetCount tracking.
		var scoreSum float64 = -1
		for i := uint32(0); i < bfCount1; i++ {
			maxScore := sdbfMaxScoreDebug(sdbf1, i, sdbf2)
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
		if denominator == 0 {
			scoreSum = -1
		}
		if scoreSum < 0 {
			return -1
		}

		return int(math.Round(100.0 * scoreSum / float64(denominator)))
	}

	// Modern: additive accumulation from zero, tracks noTargetCount.
	var scoreSum float64
	var noTargetCount uint32
	for i := uint32(0); i < bfCount1; i++ {
		s := sdbfMaxScoreDebug(sdbf1, i, sdbf2)
		if s < 0 {
			noTargetCount++
			continue
		}
		scoreSum += s
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	denominator := bfCount1 - noTargetCount
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	if denominator == 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScoreDebug calculates the maximum match of a single reference filter
// against all target filters using a toggle-gated variant of the modern
// sdbfMaxScore algorithm. When DebugRevertExactPopcount is false (the default),
// it behaves identically to sdbfMaxScore.
func sdbfMaxScoreDebug(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
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

		var match uint32
		if DebugRevertExactPopcount {
			// C++-faithful: staged early-exit heuristic before exact popcount.
			if andPopcountCut(bf1, bf2, cutOff, shortCircuitSlack) > 0 {
				match = andPopcount(bf1, bf2)
			}
		} else {
			// Modern: exact popcount directly.
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

// CompareDebug performs a pairwise comparison using a toggle-gated
// variant of the modern Compare algorithm. When both toggles are
// at their default false values, CompareDebug produces output
// identical to Compare. Individual toggles revert specific fixes:
//
//   - DebugRevertAdditiveAccumulation: when true, reverts to the
//     C++ conditional-first-assignment accumulation pattern.
//   - DebugRevertExactPopcount: when true, reverts to the C++
//     staged early-exit popcount heuristic (andPopcountCut
//     screening before exact andPopcount).
//
// This function is used exclusively for the handoff scoring
// investigation and for demonstrations. It is not part of the
// library's public scoring API and will be removed together with
// the other debug machinery when the reference correctness phase
// completes.
func CompareDebug(s1, s2 Sdbf) (int, bool) {
	if s1 == nil || s2 == nil {
		return 0, false
	}
	sdbf1, ok1 := s1.(*sdbf)
	sdbf2, ok2 := s2.(*sdbf)
	if !ok1 || !ok2 {
		return 0, false
	}
	score := sdbfScoreDebug(sdbf1, sdbf2)
	if score < 0 {
		return 0, false
	}
	return score, true
}
