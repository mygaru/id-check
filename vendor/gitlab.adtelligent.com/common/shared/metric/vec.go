package metric

import (
	"fmt"
	"gitlab.adtelligent.com/common/shared/log"
	"regexp"
	"strings"
	"sync"
)

type metricVec struct {
	newMetric func() metricWriter

	// protect metrics
	mtx     sync.Mutex
	metrics map[string]metricWriter
}

func (m *metricVec) with(labels string) (metric metricWriter) {
	var ok bool
	m.mtx.Lock()
	if metric, ok = m.metrics[labels]; !ok {
		if err := isValidLabel(labels); err != nil {
			log.Panicf("BUG: %s", err)
		}
		metric = m.newMetric()
		m.metrics[labels] = metric
	}
	m.mtx.Unlock()
	return
}

func (m *metricVec) Metrics() map[string]metricWriter {
	newMetrics := make(map[string]metricWriter)
	m.mtx.Lock()
	for k, v := range m.metrics {
		newMetrics[k] = v
	}
	m.mtx.Unlock()

	return newMetrics
}

func isValidLabel(l string) error {
	labels := strings.Split(l, ",")
	for _, label := range labels {
		if err := checkLabelValue(label); err != nil {
			return err
		}
	}

	return nil
}

// reservedLabelPrefix is a prefix which is not legal in user-supplied to use with Prometheus
const reservedLabelPrefix = "__"

var labelNameRE = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_]*$")

func checkLabelName(l string) bool {
	return labelNameRE.MatchString(l) &&
		!strings.HasPrefix(l, reservedLabelPrefix)
}

func checkLabelValue(l string) error {
	keyValue := strings.SplitN(l, "=", 2)
	if len(keyValue) < 2 {
		return fmt.Errorf("label-value pair %q must be in format key=value", l)
	}

	key := keyValue[0]
	if !checkLabelName(key) {
		return fmt.Errorf("%q is not a valid label name", key)
	}

	value := keyValue[1]
	if len(value) < 2 {
		return fmt.Errorf("%q is not a valid value", value)
	}
	if value[:1] != `"` || value[len(value)-1:] != `"` {
		return fmt.Errorf("%q must be quoted", value)
	}

	return nil
}
