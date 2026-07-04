//go:build grid

package sdhash

// Profiling grid — Layers 1 & 2: controlled dataset plan + digest/shape.
//
// Layer 1 (dataset): a deterministic (type × size × replicate) grid built by
// calling the corpus generators directly at chosen sizes, so every cell —
// including the multi-chunk stream regime (>32 MiB) — is populated for every
// type. Sizes and replicate counts follow the frozen ladder below. Nothing is
// generated here; planGrid only emits cheap metadata (a seed + size + gen fn)
// per file. Bytes are produced on demand via gridItem.generate().
//
// Layer 2 (digest + shape): shapeOf extracts the structural fingerprint of a
// computed digest (filter count, density, sparse fraction, per-filter element
// counts, hamming stats). Scoring's analytic work estimate and all "explain
// the cost by digest shape" pivots read these fields. The collectors (Layer 3)
// and benchmarks (Layer 4) are built on top of this and live in separate files.
//
// This file is gated behind the `grid` build tag and reuses the generators in
// generatecorpus_test.go (constraint widened to include `grid`).

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Frozen grid parameters
// ---------------------------------------------------------------------------

// gridMasterSeed is independent of the corpus tests' bdgMasterSeed so the grid
// dataset never collides with the anchor corpora.
const gridMasterSeed int64 = 0x5D_1A_57_A1_5E_ED_00_01

// gridSize is one rung of the size ladder: a requested byte size and the
// number of distinct replicate files to plan at that size.
type gridSize struct {
	name    string
	bytes   int
	reps    int
	multiCh bool // true when this rung exercises the stream multi-chunk path (>32 MiB)
}

// gridSizeLadder is the frozen ladder. 31M/33M straddle the 32 MiB single- vs
// multi-chunk boundary (33,554,432 bytes). Replicates taper as size grows so
// the 128 MiB rung stays affordable.
var gridSizeLadder = []gridSize{
	{"512B", 512, 32, false},
	{"4K", 4 * 1024, 32, false},
	{"64K", 64 * 1024, 32, false},
	{"512K", 512 * 1024, 16, false},
	{"4M", 4 * 1024 * 1024, 8, false},
	{"31M", 31 * 1024 * 1024, 3, false},
	{"33M", 33 * 1024 * 1024, 3, true},
	{"64M", 64 * 1024 * 1024, 2, true},
	{"128M", 128 * 1024 * 1024, 1, true},
}

// ddBlockLadder is the frozen DD block-size set. The coarse 4 MiB block is
// added only for rungs >= 64 MiB (the "find embedded data in a big file"
// regime) via ddBlocksFor.
var ddBlockLadder = []int{
	4 * 1024,
	16 * 1024,
	64 * 1024,
	256 * 1024,
	1024 * 1024,
}

const ddCoarseBlock = 4 * 1024 * 1024

// ddBlocksFor returns the DD block sizes to exercise for a file of the given
// size: the standard ladder always, plus the coarse 4 MiB block for files
// >= 64 MiB. Block sizes >= the file size are dropped (they degenerate to a
// single filter, i.e. stream mode) except we always keep at least the
// smallest block so every file has one DD configuration.
func ddBlocksFor(sizeBytes int) []int {
	var out []int
	for _, b := range ddBlockLadder {
		if b < sizeBytes {
			out = append(out, b)
		}
	}
	if sizeBytes >= 64*1024*1024 {
		out = append(out, ddCoarseBlock)
	}
	if len(out) == 0 {
		out = append(out, ddBlockLadder[0]) // smallest block, always valid
	}
	return out
}

// scoringAnchorSize is the fixed file size for the 23×23 type matrix, chosen
// to sit at the top of the real-malware range while staying single-chunk for
// stream mode.
const scoringAnchorSize = 4 * 1024 * 1024

// scoringAnchorDDBlock keeps the DD type matrix above the "too few filters"
// threshold: 4 MiB / 64 KiB ≈ 64 filters.
const scoringAnchorDDBlock = 64 * 1024

// scoringSweepPairs are the mechanism-revealing type pairs walked across the
// full size ladder (in addition to the size-fixed 23×23 matrix).
var scoringSweepPairs = [][2]string{
	{"random", "random"},
	{"pe", "pe"},
	{"sparse", "sparse"},
	{"pe", "sparse"},
	{"low_entropy", "random"},
}

// ---------------------------------------------------------------------------
// Layer 1 — deterministic dataset plan
// ---------------------------------------------------------------------------

// gridItem is one planned file: the metadata needed to regenerate its exact
// bytes plus its coordinates in the grid. Bytes are produced lazily.
type gridItem struct {
	typeName string
	typeIdx  int
	gen      func(rng *rand.Rand, size int) []byte
	sizeName string
	reqSize  int
	sizeIdx  int
	rep      int
	seed     uint64
}

// generate reproduces the file's bytes. Each file is seeded independently by
// cellSeed, so bytes are a pure deterministic function of grid coordinates and
// are stable across machines and runs.
func (it gridItem) generate() []byte {
	return it.gen(rand.New(rand.NewPCG(it.seed, 0)), it.reqSize)
}

// splitmix64 is a well-distributed finalizer used to derive independent
// per-cell seeds from the (master, type, size, rep) coordinate tuple.
func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// cellSeed derives a stable, independent 64-bit seed for one grid cell.
func cellSeed(master int64, typeIdx, sizeIdx, rep int) uint64 {
	h := uint64(master)
	h = splitmix64(h ^ (uint64(typeIdx) * 0x100000001B3))
	h = splitmix64(h ^ (uint64(sizeIdx) * 0x9E3779B97F4A7C15))
	h = splitmix64(h ^ uint64(rep))
	return h
}

// gridTypes returns the 23 generators by name, in the canonical order of
// bdgDefaultCategories. Per-category size/count overrides are intentionally
// ignored: the grid drives its own size ladder uniformly across all types.
func gridTypes() []genCatConfig {
	return bdgDefaultCategories()
}

// planGrid emits the full (type × size × replicate) plan. Cheap: no bytes are
// generated. Order is type-major, then size, then replicate.
func planGrid() []gridItem {
	cats := gridTypes()
	var out []gridItem
	for ti, cc := range cats {
		for si, gs := range gridSizeLadder {
			for r := 0; r < gs.reps; r++ {
				out = append(out, gridItem{
					typeName: cc.name,
					typeIdx:  ti,
					gen:      cc.gen,
					sizeName: gs.name,
					reqSize:  gs.bytes,
					sizeIdx:  si,
					rep:      r,
					seed:     cellSeed(gridMasterSeed, ti, si, r),
				})
			}
		}
	}
	return out
}

// planGridUpTo is planGrid limited to size rungs at or below maxBytes, for
// small-scale validation and for -max capping on constrained hardware.
func planGridUpTo(maxBytes int) []gridItem {
	all := planGrid()
	out := all[:0:0]
	for _, it := range all {
		if it.reqSize <= maxBytes {
			out = append(out, it)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Layer 2 — digest shape
// ---------------------------------------------------------------------------

// digestShape is the structural fingerprint used to explain hashing and
// scoring cost. filterElems is materialized for both modes so the scoring
// work estimate can read per-filter element counts uniformly.
type digestShape struct {
	mode        string // "stream" or "dd"
	ddBlock     int    // 0 for stream
	inputSize   uint64
	filterCount uint32
	maxElem     uint32
	density     float64 // FeatureDensity: total features / input size
	sparseCount uint32  // filters with elemCount < minElemCount (16)
	sparseFrac  float64 // sparseCount / filterCount
	totalElems  uint64  // sum of per-filter element counts
	hammingMin  uint16
	hammingMax  uint16
	hammingMean float64
	filterElems []uint16 // per-filter element counts, length == filterCount
}

// shapeOf extracts the shape of a computed digest. mode/ddBlock describe how
// the digest was produced ("stream"/0 or "dd"/blockSize). It reads unexported
// fields directly, which is why the grid harness is white-box.
func shapeOf(sd Sdbf, mode string, ddBlock int) digestShape {
	s := sd.(*sdbf)
	shape := digestShape{
		mode:        mode,
		ddBlock:     ddBlock,
		inputSize:   s.origFileSize,
		filterCount: s.bfCount,
		maxElem:     s.maxElem,
		density:     s.FeatureDensity(),
		filterElems: make([]uint16, s.bfCount),
	}

	var hmin, hmax uint16
	var hsum uint64
	for i := uint32(0); i < s.bfCount; i++ {
		ec := uint16(s.elemCount(i))
		shape.filterElems[i] = ec
		shape.totalElems += uint64(ec)
		if uint32(ec) < minElemCount {
			shape.sparseCount++
		}
		h := s.hamming[i]
		if i == 0 || h < hmin {
			hmin = h
		}
		if i == 0 || h > hmax {
			hmax = h
		}
		hsum += uint64(h)
	}
	shape.hammingMin = hmin
	shape.hammingMax = hmax
	if s.bfCount > 0 {
		shape.hammingMean = float64(hsum) / float64(s.bfCount)
		shape.sparseFrac = float64(shape.sparseCount) / float64(s.bfCount)
	}
	return shape
}

// ---------------------------------------------------------------------------
// Provenance (stamped onto every emitted dataset in Layer 3)
// ---------------------------------------------------------------------------

const gridSchemaVersion = 1

// runManifest records the environment a grid run was captured in, so a
// baseline and a later run can be compared apples-to-apples across machines.
// libCommit is injected at build time (-ldflags "-X ...gridLibCommit=<sha>")
// or left blank.
type runManifest struct {
	schemaVersion int
	goVersion     string
	goos          string
	goarch        string
	numCPU        int
	gomaxprocs    int
	cpuModel      string
	libCommit     string
	masterSeed    int64
	capturedAt    string
}

var gridLibCommit string // set via -ldflags at build time

// cpuModel returns a best-effort CPU model string for provenance. On Linux it
// reads /proc/cpuinfo; elsewhere it falls back to the architecture.
// cpuModel returns a best-effort CPU model string for provenance. On Linux it
// reads /proc/cpuinfo; on macOS it queries sysctl (the same source Go's own
// benchmark header uses); elsewhere it falls back to the architecture.
func cpuModel() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
		return runtime.GOARCH
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return runtime.GOARCH
}

func newRunManifest() runManifest {
	return runManifest{
		schemaVersion: gridSchemaVersion,
		goVersion:     runtime.Version(),
		goos:          runtime.GOOS,
		goarch:        runtime.GOARCH,
		numCPU:        runtime.NumCPU(),
		gomaxprocs:    runtime.GOMAXPROCS(0),
		cpuModel:      cpuModel(),
		libCommit:     gridLibCommit,
		masterSeed:    gridMasterSeed,
		capturedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}
