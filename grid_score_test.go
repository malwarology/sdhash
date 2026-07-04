//go:build grid

package sdhash

// Profiling grid — Layer 3 scoring collector.
//
// TestGridScoreMatrix  the 23×23 type matrix at the fixed anchor size
//                      (4 MiB; DD at 64 KiB ≈ 64 filters), stream + DD. Each
//                      cell scores all replicate pairs; cost is measured at the
//                      cell level (best-of-3 mean ns/pair, robust to timer
//                      granularity) alongside the exact analytic popcount
//                      estimate, so cost can be explained by digest shape.
//
// TestGridScoreSweep   the five mechanism-revealing pairs walked across the
//                      size ladder, showing how per-pair cost scales with size
//                      (and thus filter count) within a pair.
//
// Work estimate (scoreWorkEstimate) replicates the exact cost path in score.go:
// Compare runs andPopcount only for (non-sparse source filters) × (non-sparse
// target filters); sparse filters (elemCount < minElemCount) are skipped with
// zero popcounts. "Source" is the smaller digest after the swap.

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

// scoreWorkEstimate returns the exact number of andPopcount calls a Compare of
// the two digests performs, plus the non-sparse filter counts on each side.
func scoreWorkEstimate(a, b digestShape) (popcounts uint64, srcNonSparse, tgtNonSparse uint32) {
	src, tgt := a, b
	swap := a.filterCount > b.filterCount ||
		(a.filterCount == b.filterCount && a.filterCount > 0 &&
			a.filterElems[a.filterCount-1] > b.filterElems[b.filterCount-1])
	if swap {
		src, tgt = b, a
	}
	for _, e := range src.filterElems {
		if uint32(e) >= minElemCount {
			srcNonSparse++
		}
	}
	for _, e := range tgt.filterElems {
		if uint32(e) >= minElemCount {
			tgtNonSparse++
		}
	}
	return uint64(srcNonSparse) * uint64(tgtNonSparse), srcNonSparse, tgtNonSparse
}

type builtDigest struct {
	sd    Sdbf
	shape digestShape
}

// typeByName resolves a type name to its canonical index and generator.
func typeByName(name string) (int, func(rng *rand.Rand, size int) []byte, bool) {
	for i, cc := range gridTypes() {
		if cc.name == name {
			return i, cc.gen, true
		}
	}
	return 0, nil, false
}

// buildDigests deterministically materializes reps digests for one type at a
// given size rung, in the requested mode.
func buildDigests(name string, sizeIdx, sizeBytes, reps int, mode string, ddBlock int) []builtDigest {
	ti, gen, ok := typeByName(name)
	if !ok {
		return nil
	}
	var out []builtDigest
	for r := 0; r < reps; r++ {
		seed := cellSeed(gridMasterSeed, ti, sizeIdx, r)
		data := gen(rand.New(rand.NewPCG(seed, 0)), sizeBytes)
		if len(data) < MinFileSize {
			continue
		}
		f, err := New(data)
		if err != nil {
			continue
		}
		var sd Sdbf
		if mode == "stream" {
			sd, err = f.Compute()
		} else {
			sd, err = f.WithBlockSize(uint32(ddBlock)).Compute()
		}
		if err != nil {
			continue
		}
		out = append(out, builtDigest{sd, shapeOf(sd, mode, ddBlock)})
	}
	return out
}

// anchorRung returns the ladder rung used as the scoring-matrix anchor, clamped
// to -grid.max so the matrix still runs on capped/validation passes.
func anchorRung() (gridSize, int) {
	target := scoringAnchorSize
	if *flagGridMax < target {
		target = *flagGridMax
	}
	best, bestIdx := gridSizeLadder[0], 0
	for i, gs := range gridSizeLadder {
		if gs.bytes <= target {
			best, bestIdx = gs, i
		}
	}
	return best, bestIdx
}

var scoreMatrixHeader = []string{
	"mode", "type_a", "type_b", "pairs", "ns_per_pair",
	"popcount_est_mean", "score_mean", "src_nonsparse_mean", "tgt_nonsparse_mean",
	"score_p50", "score_max",
}

// scoreCell times the R×R sweep of a cell (best-of-3) and accumulates the
// exact estimate and score stats on the first pass.
func scoreCell(as, bs []builtDigest) (nsPerPair, estMean, scoreMean, srcMean, tgtMean, scoreP50, scoreMax float64, pairs int) {
	var bestNs int64 = math.MaxInt64
	var sumEst, sumScore, sumSrc, sumTgt float64
	var scores []float64
	for rep := 0; rep < 3; rep++ {
		t0 := time.Now()
		p := 0
		for i := range as {
			for j := range bs {
				s, _ := as[i].sd.Compare(bs[j].sd)
				p++
				if rep == 0 {
					est, src, tgt := scoreWorkEstimate(as[i].shape, bs[j].shape)
					sumEst += float64(est)
					sumSrc += float64(src)
					sumTgt += float64(tgt)
					sumScore += float64(s)
					scores = append(scores, float64(s))
				}
			}
		}
		if ns := time.Since(t0).Nanoseconds(); ns < bestNs {
			bestNs = ns
		}
		pairs = p
	}
	if pairs == 0 {
		return
	}
	st := summarize(scores)
	return float64(bestNs) / float64(pairs),
		sumEst / float64(pairs), sumScore / float64(pairs),
		sumSrc / float64(pairs), sumTgt / float64(pairs),
		st.p50, st.max, pairs
}

func TestGridScoreMatrix(t *testing.T) {
	rung, rungIdx := anchorRung()
	reps := scaledReps(rung.reps)
	t.Logf("score matrix anchored at %s (%d bytes), %d reps/type", rung.name, rung.bytes, reps)

	m := newRunManifest()
	sink := newCSVSink(t, "score_matrix.csv", m, scoreMatrixHeader)
	defer sink.close()

	modes := []struct {
		name  string
		block int
	}{{"stream", 0}, {"dd", scoringAnchorDDBlock}}
	types := gridTypes()

	ps := startProfileScope(t, "score_matrix", false)
	for _, md := range modes {
		dig := map[string][]builtDigest{}
		for _, cc := range types {
			dig[cc.name] = buildDigests(cc.name, rungIdx, rung.bytes, reps, md.name, md.block)
		}
		// For the cost-vs-work correlation summary.
		var nsPerAll, estAll []float64
		for _, ca := range types {
			for _, cb := range types {
				as, bs := dig[ca.name], dig[cb.name]
				if len(as) == 0 || len(bs) == 0 {
					continue
				}
				nsPer, estMean, scoreMean, srcMean, tgtMean, sP50, sMax, pairs := scoreCell(as, bs)
				sink.row(md.name, ca.name, cb.name, fI(pairs), fF(nsPer),
					fF(estMean), fF(scoreMean), fF(srcMean), fF(tgtMean), fF(sP50), fF(sMax))
				nsPerAll = append(nsPerAll, nsPer)
				estAll = append(estAll, estMean)
			}
		}
		r := pearson(estAll, nsPerAll)
		t.Logf("=== score matrix [%s]: %d cells, cost~work Pearson r = %.3f ===", md.name, len(nsPerAll), r)
		t.Logf("    (r near 1.0 ⇒ per-pair cost is well explained by the popcount estimate)")
	}
	ps.stop(t)
}

var scoreSweepHeader = []string{
	"mode", "pair", "type_a", "type_b", "size_name", "size_bytes",
	"pairs", "ns_per_pair", "popcount_est_mean", "score_mean", "bf_a_mean", "bf_b_mean",
}

func TestGridScoreSweep(t *testing.T) {
	m := newRunManifest()
	sink := newCSVSink(t, "score_sweep.csv", m, scoreSweepHeader)
	defer sink.close()

	modes := []struct {
		name  string
		block int
	}{{"stream", 0}, {"dd", scoringAnchorDDBlock}}

	ps := startProfileScope(t, "score_sweep", false)
	for _, md := range modes {
		for _, pair := range scoringSweepPairs {
			pairName := pair[0] + "×" + pair[1]
			for si, gs := range gridSizeLadder {
				if gs.bytes > *flagGridMax {
					continue
				}
				reps := scaledReps(gs.reps)
				as := buildDigests(pair[0], si, gs.bytes, reps, md.name, md.block)
				bs := buildDigests(pair[1], si, gs.bytes, reps, md.name, md.block)
				if len(as) == 0 || len(bs) == 0 {
					continue
				}
				nsPer, estMean, scoreMean, _, _, _, _, pairs := scoreCell(as, bs)
				var bfA, bfB float64
				for _, d := range as {
					bfA += float64(d.shape.filterCount)
				}
				for _, d := range bs {
					bfB += float64(d.shape.filterCount)
				}
				bfA /= float64(len(as))
				bfB /= float64(len(bs))
				sink.row(md.name, pairName, pair[0], pair[1], gs.name, fI(gs.bytes),
					fI(pairs), fF(nsPer), fF(estMean), fF(scoreMean), fF(bfA), fF(bfB))
				t.Logf("[%s] %-20s %-6s bf=%.0f×%.0f  est=%.0f popcounts  ns/pair=%.1f  score=%.1f",
					md.name, pairName, gs.name, bfA, bfB, estMean, nsPer, scoreMean)
			}
		}
	}
	ps.stop(t)
}
