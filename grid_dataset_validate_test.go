//go:build grid

package sdhash

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// TestGridPlan_Shape validates Layer 1 (deterministic plan) and Layer 2
// (digest + shape) at small scale: it caps the ladder low so it runs quickly
// on constrained hardware. It checks that
//
//   - the plan is the expected size (23 types × ladder × reps, capped),
//   - regeneration is deterministic (same coords → identical bytes),
//   - distinct cells produce distinct bytes,
//   - generators honor the requested size well enough to digest,
//   - shapeOf populates sane fields for both stream and DD digests.
func TestGridPlan_Shape(t *testing.T) {
	const capBytes = 64 * 1024 // validate only up to 64K rungs here
	items := planGridUpTo(capBytes)
	if len(items) == 0 {
		t.Fatal("empty plan")
	}

	// Expected count: for each type, sum reps over rungs <= capBytes.
	var repsPerType int
	for _, gs := range gridSizeLadder {
		if gs.bytes <= capBytes {
			repsPerType += gs.reps
		}
	}
	wantCount := len(gridTypes()) * repsPerType
	checkEqual(t, wantCount, len(items), "plan item count")
	t.Logf("planned %d items (%d types × %d reps up to %dB)", len(items), len(gridTypes()), repsPerType, capBytes)

	// Determinism: regenerating the same item yields identical bytes.
	it := items[len(items)/2]
	h1 := sha256.Sum256(it.generate())
	h2 := sha256.Sum256(it.generate())
	checkEqual(t, fmt.Sprintf("%x", h1), fmt.Sprintf("%x", h2), "regeneration determinism")

	// Distinctness: two different replicates of the same (type,size) differ.
	var a, b *gridItem
	for i := range items {
		if items[i].typeName == it.typeName && items[i].sizeName == it.sizeName {
			if a == nil {
				a = &items[i]
			} else if items[i].rep != a.rep {
				b = &items[i]
				break
			}
		}
	}
	if a != nil && b != nil {
		ha := sha256.Sum256(a.generate())
		hb := sha256.Sum256(b.generate())
		if ha == hb {
			t.Errorf("distinct replicates produced identical bytes: %s/%s rep %d vs %d",
				a.typeName, a.sizeName, a.rep, b.rep)
		}
	}

	// Size honoring + shape extraction across one replicate of every type at
	// the largest capped rung.
	seen := map[string]bool{}
	var digested, tooSmall int
	for i := range items {
		it := items[i]
		if it.sizeName != "64K" || it.rep != 0 {
			continue
		}
		seen[it.typeName] = true
		data := it.generate()

		if len(data) < MinFileSize {
			tooSmall++
			t.Logf("  %-24s req=%d actual=%d (below MinFileSize, not digestable)", it.typeName, it.reqSize, len(data))
			continue
		}

		f, err := New(data)
		mustNoError(t, err, it.typeName)
		sd, err := f.Compute()
		mustNoError(t, err, it.typeName)
		ss := shapeOf(sd, "stream", 0)

		df, err := New(data)
		mustNoError(t, err, it.typeName)
		dd, err := df.WithBlockSize(64 * 1024).Compute()
		mustNoError(t, err, it.typeName)
		ds := shapeOf(dd, "dd", 64*1024)

		// Sanity on shape fields.
		checkEqual(t, uint64(len(data)), ss.inputSize, it.typeName+" stream inputSize")
		checkTrue(t, ss.filterCount >= 1, it.typeName+" stream filterCount>=1")
		checkLen(t, ss.filterElems, int(ss.filterCount), it.typeName+" stream filterElems len")
		checkTrue(t, ds.filterCount >= 1, it.typeName+" dd filterCount>=1")
		checkLen(t, ds.filterElems, int(ds.filterCount), it.typeName+" dd filterElems len")

		digested++
		t.Logf("  %-24s size=%6d | stream: bf=%3d dens=%.4f sparse=%.2f hmean=%6.1f | dd: bf=%3d sparse=%.2f",
			it.typeName, len(data), ss.filterCount, ss.density, ss.sparseFrac, ss.hammingMean,
			ds.filterCount, ds.sparseFrac)
	}
	checkEqual(t, len(gridTypes()), len(seen), "all types covered at 64K")
	t.Logf("digested %d types at 64K, %d below MinFileSize", digested, tooSmall)
}

// TestGridDDBlocksFor validates the DD block selection, including the coarse
// 4 MiB block appearing only at >= 64 MiB.
func TestGridDDBlocksFor(t *testing.T) {
	cases := []struct {
		size int
		want []int
	}{
		{512, []int{4 * 1024}},                       // smaller than every block → smallest kept
		{64 * 1024, []int{4 * 1024, 16 * 1024}},      // 64K file: only blocks strictly < 64K
		{4 * 1024 * 1024, ddBlockLadder},             // 4M file: full ladder, no coarse
		{64 * 1024 * 1024, append(append([]int{}, ddBlockLadder...), ddCoarseBlock)}, // coarse appears
	}
	for _, c := range cases {
		got := ddBlocksFor(c.size)
		checkEqual(t, fmt.Sprint(c.want), fmt.Sprint(got), fmt.Sprintf("ddBlocksFor(%d)", c.size))
	}
}
