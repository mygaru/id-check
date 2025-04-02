package metric

import (
	"fmt"
	"gitlab.adtelligent.com/common/shared/util"
	"io"
)

type CounterVecSafe struct {
	*metricVecSafe
}

func NewCounterVecSafe(name string) *CounterVecSafe {
	m := &CounterVecSafe{
		metricVecSafe: &metricVecSafe{
			metrics:   make(map[string]metricWriter),
			newMetric: func() metricWriter { return &Counter{} },
		},
	}
	registerMetric(name, m)
	return m
}

func (m *CounterVecSafe) IsEmpty() bool {
	for _, c := range m.Metrics() {
		if !c.IsEmpty() {
			return false
		}
	}
	return true
}

func (m *CounterVecSafe) WriteJSON(w io.Writer, prefix string) {
	fmt.Fprintf(w, "{\n")
	metrics := m.Metrics()
	i := 0
	for _, kv := range util.SortMapByKey(metrics) {
		c := kv.V.(*Counter)
		if c.IsEmpty() {
			// skip empty counter
			continue
		}
		if i > 0 {
			fmt.Fprintf(w, ",\n")
		}
		i++
		fmt.Fprintf(w, "%s\t%q: %d", prefix, kv.K, c.Get())
	}
	fmt.Fprintf(w, "\n%s}", prefix)
}

func (m *CounterVecSafe) WritePrometheus(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	metrics := m.Metrics()
	for label, m := range metrics {
		metric := m.(*Counter)
		fmt.Fprintf(w, "%s{%s} %d\n", name, label, metric.Get())
	}
}

func (m *CounterVecSafe) With(labels string) *Counter {
	return m.with(labels).(*Counter)
}
