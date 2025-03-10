package metric

import (
	"gitlab.adtelligent.com/common/shared/log"
	"sync"
)

type metricVecSafe struct {
	newMetric func() metricWriter

	// protect metrics
	mtx     sync.Mutex
	metrics map[string]metricWriter
}

var counterVecSafeWrongLabel = NewCounter("counterVecSafeWrongLabel")

func (m *metricVecSafe) with(labels string) (metric metricWriter) {
	var ok bool
	m.mtx.Lock()
	if err := isValidLabel(labels); err != nil {
		log.Errorf("VecMetricBUG: %s", err)
		counterVecSafeWrongLabel.Inc()
		labels = "invalid"
	}
	if metric, ok = m.metrics[labels]; !ok {
		metric = m.newMetric()
		m.metrics[labels] = metric
	}
	m.mtx.Unlock()
	return
}

func (m *metricVecSafe) Metrics() map[string]metricWriter {
	newMetrics := make(map[string]metricWriter)
	m.mtx.Lock()
	for k, v := range m.metrics {
		newMetrics[k] = v
	}
	m.mtx.Unlock()

	return newMetrics
}
