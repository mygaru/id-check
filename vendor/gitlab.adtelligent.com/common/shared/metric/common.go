// Package metric provides thread-safe and goroutine-safe metrics.
package metric

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"

	"gitlab.adtelligent.com/common/shared/log"
	"gitlab.adtelligent.com/common/shared/util"
)

type metricWriter interface {
	IsEmpty() bool
	WriteJSON(w io.Writer, newlinePrefix string)
	WritePrometheus(w io.Writer, name string)
}

var (
	metricsMap     = make(map[string]metricWriter)
	metricsMapLock sync.Mutex
)

func registerMetric(name string, mw metricWriter) {
	if len(name) == 0 {
		log.Panicf("BUG: metric name cannot be empty")
	}
	if strings.ContainsAny(name, ",/") {
		log.Panicf("BUG: metric name %q mustn't contain ',' and '/' chars", name)
	}
	metricsMapLock.Lock()
	_, exists := metricsMap[name]
	if !exists {
		metricsMap[name] = mw
	}
	metricsMapLock.Unlock()
	if exists {
		log.Panicf("BUG: metric with the name %q already exists", name)
	}
}

var (
	metricRequests           = NewCounter("metricRequests")
	prometheusMetricRequests = NewCounter("prometheusMetricRequests")
	metricInvalidPathError   = NewCounter("metricInvalidPathError")
	metricInvalidRegexpError = NewCounter("metricInvalidRegexpError")
)

var strRegexpPrefix = []byte("r:")

func getAllMetricNames() []string {
	var a []string
	metricsMapLock.Lock()
	for _, kv := range util.SortMapByKey(metricsMap) {
		a = append(a, kv.K.(string))
	}
	metricsMapLock.Unlock()
	return a
}

// HTTPHandler writes metrics listed in the trailing HTTP path's part after '/'
// into ctx.
//
// Metrics are written into ctx using JSON encoding.
func HTTPHandler(ctx *fasthttp.RequestCtx, path []byte) {
	metricRequests.Inc()

	n := bytes.LastIndexByte(path, '/')
	if n < 0 {
		metricInvalidPathError.Inc()
		ctx.Logger().Printf("Invalid HTTP path=%q. It should contain at least one '/'", path)
		ctx.Error("Invalid HTTP path", fasthttp.StatusBadRequest)
		return
	}

	var metricNames []string
	s := path[n+1:]
	if len(s) == 0 {
		metricNames = getAllMetricNames()
	} else if bytes.HasPrefix(s, strRegexpPrefix) {
		s = s[len(strRegexpPrefix):]
		r, err := regexp.Compile(string(s))
		if err != nil {
			metricInvalidRegexpError.Inc()
			ctx.Logger().Printf("Invalid metric regexp=%q: %s", s, err)
			ctx.Error("Invalid regexp", fasthttp.StatusBadRequest)
			return
		}
		for _, name := range getAllMetricNames() {
			if r.MatchString(name) {
				metricNames = append(metricNames, name)
			}
		}
	} else {
		metricNames = strings.Split(string(s), ",")
	}

	if err := WriteJSON(ctx, metricNames); err != nil {
		ctx.Logger().Printf("%s", err)
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}
	ctx.SetContentType("application/json")
}

// HTTPPrometheusHandler writes metrics accordingly to Prometheus format
func HTTPPrometheusHandler(ctx io.Writer) {
	prometheusMetricRequests.Inc()
	metricNames := getAllMetricNames()
	metricsMapLock.Lock()
	for _, name := range metricNames {
		m := metricsMap[name]
		name = ToPrometheusMetricName(name)
		m.WritePrometheus(ctx, name)
	}
	metricsMapLock.Unlock()
}

var metricUnknownError = NewCounter("metricUnknownError")

// WriteJSON writes the given metrics into w using JSON encoding.
func WriteJSON(w io.Writer, metricNames []string) error {
	return WriteJSONPrefix(w, metricNames, "")
}

// WriteJSONPrefix write the given metrics into w using JSON encoding
// and the given newline prefix.
func WriteJSONPrefix(w io.Writer, metricNames []string, newlinePrefix string) error {
	fmt.Fprintf(w, "{\n")

	prefix := newlinePrefix + "\t"
	metricsMapLock.Lock()
	i := 0
	for _, name := range metricNames {
		m := metricsMap[name]
		if m == nil {
			metricsMapLock.Unlock()
			metricUnknownError.Inc()
			return fmt.Errorf("Unknown metric %q", name)
		}
		if m.IsEmpty() {
			// skip empty metric
			continue
		}

		if i > 0 {
			fmt.Fprintf(w, ",\n")
		}
		i++
		fmt.Fprintf(w, "%s%q: ", prefix, name)
		m.WriteJSON(w, prefix)
	}
	metricsMapLock.Unlock()

	fmt.Fprintf(w, "\n%s}", newlinePrefix)
	return nil
}

// ToPrometheusMetricName replace illegal for Prometheus characters by "_"
func ToPrometheusMetricName(name string) string {
	var b []rune
	for i, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':' || (c >= '0' && c <= '9' && i > 0)) {
			c = '_'
		}
		b = append(b, c)
	}
	return string(b)
}
