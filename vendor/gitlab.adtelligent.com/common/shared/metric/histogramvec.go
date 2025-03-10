package metric

import (
	"fmt"
	"gitlab.adtelligent.com/common/shared/util"
	"io"
)

type HistogramVec struct {
	*metricVec
}

// NewHistogramVec creates new vector histogram metric with the given name.
func NewHistogramVec(name string) *HistogramVec {
	return NewHistogramExtVec(name, &HistogramConf{})
}

// NewHistogramExtVec creates new vector histogram metric with given the name and config
func NewHistogramExtVec(name string, cfg *HistogramConf) *HistogramVec {
	m := &HistogramVec{
		metricVec: &metricVec{
			metrics:   make(map[string]metricWriter),
			newMetric: func() metricWriter { return CreateHistogram(cfg) },
		},
	}
	registerMetric(name, m)
	return m
}

func (m *HistogramVec) IsEmpty() bool {
	for _, h := range m.Metrics() {
		if !h.IsEmpty() {
			return false
		}
	}
	return true
}

func (m *HistogramVec) WriteJSON(w io.Writer, prefix string) {
	fmt.Fprintf(w, "{\n")
	metrics := m.Metrics()
	prefix += "\t"
	i := 0
	for _, kv := range util.SortMapByKey(metrics) {
		h := kv.V.(*Histogram)
		if h.IsEmpty() {
			// skip empty histogram
			continue
		}
		s := h.s2.Load().(*Sample)
		if i > 0 {
			fmt.Fprintf(w, ",\n")
		}
		i++
		fmt.Fprintf(w, "%s%q: ", prefix, kv.K)
		s.writeJSON(w, prefix, h.percentiles, h.interval)
	}
	fmt.Fprintf(w, "\n%s}", prefix[:len(prefix)-1])
}

func (m *HistogramVec) WritePrometheus(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s summary\n", name)
	metrics := m.Metrics()
	for label, m := range metrics {
		metric := m.(*Histogram)
		s := metric.s2.Load().(*Sample)
		sampleWritePrometheus(w, s, metric, name, label)
	}
}

func sampleWritePrometheus(w io.Writer, s *Sample, metric *Histogram, name, label string) {
	s.lock.Lock()
	pcs := getPercentiles(s.samples, s.min, s.max, metric.percentiles)
	for i, p := range pcs {
		fmt.Fprintf(w, "%s{%s,quantile=\"%.4f\"} %.6f\n", name, label, metric.percentiles[i]/100, p)
	}
	avg, _ := getAvgStdDev(s.samples)
	fmt.Fprintf(w, "%s_sum{%s} %v\n", name, label, float64(s.count)*avg)
	fmt.Fprintf(w, "%s_count{%s} %v\n", name, label, s.count)
	s.lock.Unlock()
}

func (m *HistogramVec) With(labels string) *Histogram {
	return m.with(labels).(*Histogram)
}
