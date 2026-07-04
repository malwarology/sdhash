//go:build grid

package sdhash

// Profiling grid — Layer 3 shared infrastructure.
//
// Common machinery for the hashing and scoring collectors: duration statistics
// and log-scale histograms (printed summaries), a CSV sink stamped with a run
// manifest (the raw dataset the future web vis tool will read), and Go-native
// profile capture (cpu/mem/block/mutex + execution trace).
//
// Nothing here is third-party: encoding/csv, runtime/pprof, and runtime/trace
// are all standard library.

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Flags (registered under the grid tag; set via `go test -tags grid -grid.x=`)
// ---------------------------------------------------------------------------

var (
	flagGridOut       = flag.String("grid.out", "", "output directory for CSV + profiles (default: a temp dir)")
	flagGridMax       = flag.Int("grid.max", 128*1024*1024, "cap: skip size rungs larger than this many bytes")
	flagGridRepScale  = flag.Float64("grid.repscale", 1.0, "scale replicate counts (e.g. 0.25 for a quick pass)")
	flagGridProfile   = flag.Bool("grid.profile", true, "capture cpu/mem/block/mutex profiles per run")
	flagGridTrace     = flag.Bool("grid.trace", false, "capture an execution trace (concurrent runs only)")
	flagGridWidths    = flag.String("grid.widths", "", "concurrency widths, comma-separated (default: 1,NumCPU,4*NumCPU)")
	flagGridMemBudget = flag.Int64("grid.membudget", 2<<30, "resident byte budget for concurrent batches")
	flagGridType      = flag.String("grid.type", "", "restrict to a single type name (isolated concurrent runs)")
)

// gridOutDir resolves the output directory once, creating a timestamped temp
// dir when -grid.out is unset.
var gridOutDirOnce string

func gridOutDir(tb testing.TB) string {
	if gridOutDirOnce != "" {
		return gridOutDirOnce
	}
	dir := *flagGridOut
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "gridout-"+time.Now().UTC().Format("20060102T150405"))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("mkdir %s: %v", dir, err)
	}
	gridOutDirOnce = dir
	return dir
}

// gridWidths returns the concurrency widths to sweep.
func gridWidths() []int {
	if *flagGridWidths == "" {
		nc := runtime.NumCPU()
		return dedupInts([]int{1, nc, 4 * nc})
	}
	var out []int
	for _, p := range strings.Split(*flagGridWidths, ",") {
		if v, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && v > 0 {
			out = append(out, v)
		}
	}
	return dedupInts(out)
}

func dedupInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// scaledReps applies -grid.repscale, always keeping at least one replicate.
func scaledReps(r int) int {
	s := int(math.Round(float64(r) * *flagGridRepScale))
	if s < 1 {
		s = 1
	}
	return s
}

// planGridScaledCapped is the plan used by the collectors: size rungs above
// -grid.max are dropped and replicate counts are scaled by -grid.repscale.
func planGridScaledCapped() []gridItem {
	cats := gridTypes()
	var out []gridItem
	for ti, cc := range cats {
		for si, gs := range gridSizeLadder {
			if gs.bytes > *flagGridMax {
				continue
			}
			reps := scaledReps(gs.reps)
			for r := 0; r < reps; r++ {
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

// sortedKeys returns map keys sorted lexically.
func sortedKeys(m map[string][]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// sortedIntKeys returns integer map keys sorted ascending.
func sortedIntKeys(m map[int][]float64) []int {
	ks := make([]int, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

// ladderOrder returns the size-name keys of m ordered by their position on the
// size ladder rather than lexically.
func ladderOrder(m map[string][]float64) []string {
	pos := map[string]int{}
	for i, gs := range gridSizeLadder {
		pos[gs.name] = i
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(a, b int) bool { return pos[ks[a]] < pos[ks[b]] })
	return ks
}

// pearson returns the Pearson correlation coefficient of xs and ys.
func pearson(xs, ys []float64) float64 {
	n := len(xs)
	if n == 0 || n != len(ys) {
		return math.NaN()
	}
	var mx, my float64
	for i := range xs {
		mx += xs[i]
		my += ys[i]
	}
	mx /= float64(n)
	my /= float64(n)
	var sxy, sxx, syy float64
	for i := range xs {
		dx, dy := xs[i]-mx, ys[i]-my
		sxy += dx * dy
		sxx += dx * dx
		syy += dy * dy
	}
	if sxx == 0 || syy == 0 {
		return math.NaN()
	}
	return sxy / math.Sqrt(sxx*syy)
}

// ---------------------------------------------------------------------------
// Duration statistics + histogram
// ---------------------------------------------------------------------------

type distStats struct {
	n                             int
	min, p50, p90, p99, max, mean float64
}

// summarize computes order statistics over xs (does not mutate the input).
func summarize(xs []float64) distStats {
	if len(xs) == 0 {
		return distStats{}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	var sum float64
	for _, v := range s {
		sum += v
	}
	pct := func(p float64) float64 {
		if len(s) == 1 {
			return s[0]
		}
		idx := int(math.Ceil(p/100*float64(len(s)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(s) {
			idx = len(s) - 1
		}
		return s[idx]
	}
	return distStats{
		n:    len(s),
		min:  s[0],
		p50:  pct(50),
		p90:  pct(90),
		p99:  pct(99),
		max:  s[len(s)-1],
		mean: sum / float64(len(s)),
	}
}

// nsString formats a nanosecond value as a human duration.
func nsString(ns float64) string {
	return time.Duration(int64(ns)).String()
}

func (d distStats) String() string {
	if d.n == 0 {
		return "(no samples)"
	}
	return fmt.Sprintf("n=%d min=%s p50=%s p90=%s p99=%s max=%s mean=%s",
		d.n, nsString(d.min), nsString(d.p50), nsString(d.p90), nsString(d.p99), nsString(d.max), nsString(d.mean))
}

// logHistogram renders an ASCII log-scale histogram of durations (ns). It is
// meant for the printed summary; the CSV carries the raw per-op rows.
func logHistogram(xs []float64, width int) string {
	if len(xs) == 0 {
		return "(no samples)"
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, v := range xs {
		if v <= 0 {
			v = 1
		}
		l := math.Log10(v)
		if l < lo {
			lo = l
		}
		if l > hi {
			hi = l
		}
	}
	const buckets = 12
	if hi <= lo {
		hi = lo + 1
	}
	counts := make([]int, buckets)
	for _, v := range xs {
		if v <= 0 {
			v = 1
		}
		b := int((math.Log10(v) - lo) / (hi - lo) * float64(buckets-1))
		if b < 0 {
			b = 0
		}
		if b >= buckets {
			b = buckets - 1
		}
		counts[b]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	var sb strings.Builder
	for b := 0; b < buckets; b++ {
		edge := math.Pow(10, lo+(hi-lo)*float64(b)/float64(buckets))
		bar := 0
		if maxCount > 0 {
			bar = counts[b] * width / maxCount
		}
		_, _ = fmt.Fprintf(&sb, "  %10s |%-*s %d\n", nsString(edge), width, strings.Repeat("#", bar), counts[b])
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// CSV sink (raw dataset for downstream visualization)
// ---------------------------------------------------------------------------

type csvSink struct {
	f *os.File
	w *csv.Writer
}

// newCSVSink opens path, writes the manifest as leading `#` comment lines
// (pandas: read_csv(comment='#')), then the header row.
func newCSVSink(tb testing.TB, name string, m runManifest, header []string) *csvSink {
	dir := gridOutDir(tb)
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		tb.Fatalf("create %s: %v", path, err)
	}
	manifest := fmt.Sprintf(
		"# schema_version=%d\n"+
			"# go_version=%s goos=%s goarch=%s\n"+
			"# num_cpu=%d gomaxprocs=%d cpu_model=%q\n"+
			"# lib_commit=%s master_seed=%d captured_at=%s\n",
		m.schemaVersion,
		m.goVersion, m.goos, m.goarch,
		m.numCPU, m.gomaxprocs, m.cpuModel,
		m.libCommit, m.masterSeed, m.capturedAt,
	)
	if _, err := f.WriteString(manifest); err != nil {
		tb.Fatalf("write manifest: %v", err)
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		tb.Fatalf("write header: %v", err)
	}
	tb.Logf("CSV → %s", path)
	return &csvSink{f: f, w: w}
}

func (c *csvSink) row(vals ...string) {
	_ = c.w.Write(vals)
}

func (c *csvSink) close() {
	c.w.Flush()
	_ = c.f.Close()
}

// small formatting helpers for CSV cells
func fI(v int) string     { return strconv.Itoa(v) }
func fI64(v int64) string { return strconv.FormatInt(v, 10) }
func fU(v uint64) string  { return strconv.FormatUint(v, 10) }
func fF(v float64) string { return strconv.FormatFloat(v, 'g', 6, 64) }

// ---------------------------------------------------------------------------
// Profile capture (Go-native)
// ---------------------------------------------------------------------------

// profileScope captures cpu/mem/block/mutex profiles (and optionally a trace)
// over the region between start and the returned stop func. Files are named
// <name>.<kind>.pprof in the grid output dir.
type profileScope struct {
	name    string
	dir     string
	cpuF    *os.File
	traceF  *os.File
	profile bool
	tracing bool
}

func startProfileScope(tb testing.TB, name string, wantTrace bool) *profileScope {
	ps := &profileScope{name: name, dir: gridOutDir(tb), profile: *flagGridProfile, tracing: wantTrace && *flagGridTrace}
	if ps.profile {
		runtime.SetBlockProfileRate(1)     // sample every blocking event
		runtime.SetMutexProfileFraction(1) // sample every contention event
		f, err := os.Create(filepath.Join(ps.dir, name+".cpu.pprof"))
		if err != nil {
			tb.Fatalf("create cpu profile: %v", err)
		}
		ps.cpuF = f
		if err := pprof.StartCPUProfile(f); err != nil {
			tb.Fatalf("start cpu profile: %v", err)
		}
	}
	if ps.tracing {
		f, err := os.Create(filepath.Join(ps.dir, name+".trace"))
		if err != nil {
			tb.Fatalf("create trace: %v", err)
		}
		ps.traceF = f
		if err := trace.Start(f); err != nil {
			tb.Fatalf("start trace: %v", err)
		}
	}
	return ps
}

func (ps *profileScope) stop(tb testing.TB) {
	if ps.tracing {
		trace.Stop()
		_ = ps.traceF.Close()
	}
	if ps.profile {
		pprof.StopCPUProfile()
		_ = ps.cpuF.Close()
		writeLookup := func(kind string) {
			p := pprof.Lookup(kind)
			if p == nil {
				return
			}
			f, err := os.Create(filepath.Join(ps.dir, ps.name+"."+kind+".pprof"))
			if err != nil {
				tb.Logf("create %s profile: %v", kind, err)
				return
			}
			_ = p.WriteTo(f, 0)
			_ = f.Close()
		}
		writeLookup("allocs")
		writeLookup("block")
		writeLookup("mutex")
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
}
