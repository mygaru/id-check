package metric

import (
	"fmt"
	"gitlab.adtelligent.com/common/shared/util"
	"io"
)

type HistogramVecSafe struct {
	*metricVecSafe
}

func NewHistogramVecSafe(name string) *HistogramVecSafe {
	return NewHistogramExtVecSafe(name, &HistogramConf{})
}

func NewHistogramExtVecSafe(name string, cfg *HistogramConf) *HistogramVecSafe {
	m := &HistogramVecSafe{
		metricVecSafe: &metricVecSafe{
			metrics:   make(map[string]metricWriter),
			newMetric: func() metricWriter { return CreateHistogram(cfg) },
		},
	}
	registerMetric(name, m)
	return m
}

func (m *HistogramVecSafe) IsEmpty() bool {
	for _, h := range m.Metrics() {
		if !h.IsEmpty() {
			return false
		}
	}
	return true
}

func (m *HistogramVecSafe) WriteJSON(w io.Writer, prefix string) {
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

func (m *HistogramVecSafe) WritePrometheus(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s summary\n", name)
	metrics := m.Metrics()
	for label, m := range metrics {
		metric := m.(*Histogram)
		s := metric.s2.Load().(*Sample)
		sampleWritePrometheus(w, s, metric, name, label)
	}
}

func (m *HistogramVecSafe) With(labels string) *Histogram {
	return m.with(labels).(*Histogram)
}
