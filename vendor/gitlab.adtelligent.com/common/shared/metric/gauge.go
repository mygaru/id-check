package metric

import (
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

// GaugeFunc is called when gauge's value should be consumed by metric's reader.
//
// The function must be safe for concurrent use.
type GaugeFunc func() uint64

// Gauge implements gauge.
type Gauge struct {
	f GaugeFunc
}

// NewGauge creates new gauge with the given name and the given GaugeFunc.
func NewGauge(name string, f GaugeFunc) *Gauge {
	g := &Gauge{
		f: f,
	}
	registerMetric(name, g)
	return g
}

func (g *Gauge) IsEmpty() bool {
	return g.f() == 0
}

func (g *Gauge) WriteJSON(w io.Writer, newlinePrefix string) {
	v := g.f()
	fmt.Fprintf(w, "%d", v)
}

func (g *Gauge) WritePrometheus(w io.Writer, name string) {
	v := g.f()
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %d\n", name, v)
}

var startTime = time.Now()

func init() {
	updateMemStats()
	go func() {
		for {
			time.Sleep(15 * time.Second)
			updateMemStats()
		}
	}()

	NewGauge("uptime", func() uint64 { return uint64(time.Since(startTime).Seconds()) })
	NewGauge("runtimeGOMAXPROCS", func() uint64 { return uint64(runtime.GOMAXPROCS(-1)) })
	NewGauge("runtimeNumCPU", func() uint64 { return uint64(runtime.NumCPU()) })
	NewGauge("runtimeNumGoroutine", func() uint64 { return uint64(runtime.NumGoroutine()) })
	NewGauge("runtimeNumCgoCall", func() uint64 { return uint64(runtime.NumCgoCall()) })

	NewGauge("memoryInUse", func() uint64 { return uint64(memStat().Alloc) })
	NewGauge("memoryAllocated", func() uint64 { return uint64(memStat().TotalAlloc) })
	NewGauge("memoryRequestedFromOS", func() uint64 { return uint64(memStat().Sys) })
	NewGauge("memoryNumGC", func() uint64 { return uint64(memStat().NumGC) })
	NewGauge("memoryGCCPUFractionMilli", func() uint64 { return uint64(memStat().GCCPUFraction * 100000) })
	NewGauge("memoryLookups", func() uint64 { return uint64(memStat().Lookups) })
	NewGauge("memoryMallocs", func() uint64 { return uint64(memStat().Mallocs) })
	NewGauge("memoryFrees", func() uint64 { return uint64(memStat().Frees) })
	NewGauge("memoryHeapObjects", func() uint64 { return uint64(memStat().HeapObjects) })
	NewGauge("memoryStackInuse", func() uint64 { return uint64(memStat().StackInuse) })
	NewGauge("memoryStackSys", func() uint64 { return uint64(memStat().StackSys) })
	NewGauge("memoryNextGC", func() uint64 { return uint64(memStat().NextGC) })
	NewGauge("memoryPauseTotalNs", func() uint64 { return uint64(memStat().PauseTotalNs) })
}

var memStats atomic.Value

func memStat() *runtime.MemStats {
	return memStats.Load().(*runtime.MemStats)
}

func updateMemStats() {
	var stat runtime.MemStats
	runtime.ReadMemStats(&stat)
	memStats.Store(&stat)
}
