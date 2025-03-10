package metric

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fastrand"
)

// Histogram provides sample-based and interval-based histogram metric.
type Histogram struct {
	s1          atomic.Value
	s2          atomic.Value
	pCache      atomic.Value
	interval    time.Duration
	percentiles []float64
}

// HistogramConf contains required configuration fields
type HistogramConf struct {
	SampleSize  int
	Interval    time.Duration
	Percentiles []float64
}

func (hc *HistogramConf) validate() {
	if hc.SampleSize <= 0 {
		hc.SampleSize = 1024
	}
	if hc.Interval <= time.Millisecond {
		hc.Interval = 5 * time.Minute
	}
	if len(hc.Percentiles) == 0 {
		hc.Percentiles = []float64{25.0, 50.0, 75.0, 84.1, 90.0, 95.0, 97.7, 99.0, 99.9}
	}
}

type pCacheEntry struct {
	t time.Time
	v float64
}

// NewHistogram creates new histogram metric with the given name.
func NewHistogram(name string) *Histogram {
	return NewHistogramExt(name, &HistogramConf{})
}

// NewHistogramExt creates new histogram metric with the given name, the given
// sample size, the given interval and the given percentiles.
func NewHistogramExt(name string, c *HistogramConf) *Histogram {
	h := CreateHistogram(c)
	registerMetric(name, h)
	return h
}

func CreateHistogram(c *HistogramConf) *Histogram {
	c.validate()
	h := &Histogram{
		percentiles: c.Percentiles,
		interval:    c.Interval,
	}
	h.s1.Store(NewSample(c.SampleSize))
	h.s2.Store(NewSample(c.SampleSize))
	h.pCache.Store(make(map[float64]*pCacheEntry))
	go func() {
		for {
			time.Sleep(c.Interval)
			s1 := h.s1.Load().(*Sample)
			s2 := h.s2.Load().(*Sample)
			s2.Reset()
			h.s2.Store(s1)
			h.s1.Store(s2)
		}
	}()
	return h
}

// Update updates the histogram with the given value.
func (h *Histogram) Update(v float64) {
	h.s1.Load().(*Sample).Update(v)
	h.s2.Load().(*Sample).Update(v)
}

// UpdateDuration updates the histogram with duration in seconds elapsed
// from the given startTime.
func (h *Histogram) UpdateDuration(startTime time.Time) {
	h.Update(time.Since(startTime).Seconds())
}

// Percentile returns percentile value for the given p.
func (h *Histogram) Percentile(p float64) float64 {
	pCache := h.pCache.Load().(map[float64]*pCacheEntry)
	e := pCache[p]
	if e != nil && time.Since(e.t) < time.Second {
		return e.v
	}

	s := h.s2.Load().(*Sample)
	v := s.Percentile(p)
	if s.Count() == 0 {
		return v
	}

	pCacheNew := make(map[float64]*pCacheEntry, len(pCache)+1)
	for k, v := range pCache {
		pCacheNew[k] = v
	}

	e = &pCacheEntry{
		t: time.Now(),
		v: v,
	}
	pCacheNew[p] = e
	h.pCache.Store(pCacheNew)
	return e.v
}

func (h *Histogram) IsEmpty() bool {
	s := h.s2.Load().(*Sample)
	return s.Count() == 0
}

func (h *Histogram) WriteJSON(w io.Writer, newlinePrefix string) {
	s := h.s2.Load().(*Sample)
	s.writeJSON(w, newlinePrefix, h.percentiles, h.interval)
}

func (h *Histogram) WritePrometheus(w io.Writer, name string) {
	h.s2.Load().(*Sample).writePrometheus(w, name, h.percentiles, h.interval)
}

type Sample struct {
	lock    sync.Mutex
	rng     fastrand.RNG
	samples []float64
	count   uint32
	min     float64
	max     float64
	t       time.Time
}

func NewSample(sampleSize int) *Sample {
	s := &Sample{
		samples: make([]float64, 0, sampleSize),
	}
	s.Reset()
	return s
}

func (s *Sample) Reset() {
	s.lock.Lock()
	s.samples = s.samples[:0]
	s.count = 0
	s.min = math.Inf(1)
	s.max = math.Inf(-1)
	s.t = time.Now()
	s.lock.Unlock()
}

func (s *Sample) Update(v float64) {
	s.lock.Lock()
	if s.count < (1<<32)-1 {
		s.count++
	}
	if v < s.min {
		s.min = v
	}
	if v > s.max {
		s.max = v
	}
	if s.count <= uint32(cap(s.samples)) {
		s.samples = append(s.samples, v)
	} else {
		x := s.rng.Uint32n(s.count)
		if x < uint32(len(s.samples)) {
			s.samples[x] = v
		}
	}
	s.lock.Unlock()
}

func (s *Sample) Count() uint32 {
	s.lock.Lock()
	n := s.count
	s.lock.Unlock()
	return n
}

func (s *Sample) writePrometheus(w io.Writer, name string, percentiles []float64, interval time.Duration) {
	s.lock.Lock()
	pcs := getPercentiles(s.samples, s.min, s.max, percentiles)
	fmt.Fprintf(w, "# TYPE %s summary\n", name)
	for i, p := range pcs {
		fmt.Fprintf(w, "%s{quantile=\"%.4f\"} %.6f\n", name, percentiles[i]/100, p)
	}
	fmt.Fprintf(w, "%s{quantile=\"1.0000\"} %.6f\n", name, s.max)
	avg, _ := getAvgStdDev(s.samples)
	fmt.Fprintf(w, "%s_sum %v\n", name, float64(s.count)*avg)
	fmt.Fprintf(w, "%s_count %v\n", name, s.count)
	s.lock.Unlock()
}

func (s *Sample) writeJSON(w io.Writer, newlinePrefix string, percentiles []float64, interval time.Duration) {
	fmt.Fprintf(w, "{\n")

	s.lock.Lock()
	duration := time.Since(s.t).Seconds()
	var qps float64
	if duration > 0 {
		qps = float64(s.count) / duration
	}
	avg, stddev := getAvgStdDev(s.samples)
	fmt.Fprintf(w, "%s\t%q: %d,\n", newlinePrefix, "count", s.count)
	fmt.Fprintf(w, "%s\t%q: %.3f,\n", newlinePrefix, "interval", interval.Seconds())
	fmt.Fprintf(w, "%s\t%q: %.3f,\n", newlinePrefix, "duration", duration)
	fmt.Fprintf(w, "%s\t%q: %.3f,\n", newlinePrefix, "qps", qps)
	fmt.Fprintf(w, "%s\t%q: %.6f,\n", newlinePrefix, "min", fixJSONFloat(s.min))
	fmt.Fprintf(w, "%s\t%q: %.6f,\n", newlinePrefix, "avg", fixJSONFloat(avg))
	fmt.Fprintf(w, "%s\t%q: %.6f,\n", newlinePrefix, "max", fixJSONFloat(s.max))
	fmt.Fprintf(w, "%s\t%q: %.6f,\n", newlinePrefix, "stddev", fixJSONFloat(stddev))
	pcs := getPercentiles(s.samples, s.min, s.max, percentiles)
	s.lock.Unlock()

	fmt.Fprintf(w, "%s\t%q: {\n", newlinePrefix, "percentiles")
	comma := ","
	for i, p := range pcs {
		if i == len(pcs)-1 {
			comma = ""
		}
		fmt.Fprintf(w, "%s\t\t\"%.1f\": %.6f%s\n", newlinePrefix, percentiles[i], fixJSONFloat(p), comma)
	}
	fmt.Fprintf(w, "%s\t}\n", newlinePrefix)

	fmt.Fprintf(w, "%s}", newlinePrefix)
}

func (s *Sample) Percentile(p float64) float64 {
	s.lock.Lock()
	pcs := getPercentiles(s.samples, s.min, s.max, []float64{p})
	s.lock.Unlock()

	return pcs[0]
}

func fixJSONFloat(v float64) float64 {
	// JSON doesn't support Inf and NaN, so substitute them by 0.
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

func getPercentiles(a []float64, min, max float64, percentiles []float64) []float64 {
	sort.Float64Slice(a).Sort()
	n := len(a)
	nf := float64(n)
	pcs := make([]float64, len(percentiles))
	for j, p := range percentiles {
		i := int(0.01*p*nf + 0.5)
		var v float64
		if i >= n {
			v = max
		} else if i < 0 {
			v = min
		} else {
			v = a[i]
		}
		pcs[j] = v
	}
	return pcs
}

func getAvgStdDev(a []float64) (avg, stddev float64) {
	n := float64(len(a))
	if n == 0 {
		return 0, 0
	}

	var sum float64
	for _, v := range a {
		sum += v
	}
	avg = sum / n

	var devSum float64
	for _, v := range a {
		dev := v - avg
		devSum += dev * dev
	}
	stddev = math.Sqrt(devSum) / n
	return
}
