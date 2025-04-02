package metric

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Counter is an uint64 counter.
type Counter struct {
	n uint64
}

// Inc increments counter by 1.
func (m *Counter) Inc() uint64 {
	return atomic.AddUint64(&m.n, 1)
}

// Dec decrements counter by 1.
func (m *Counter) Dec() {
	atomic.AddUint64(&m.n, ^uint64(0))
}

// Add adds n to the counter.
func (m *Counter) Add(n int) {
	atomic.AddUint64(&m.n, uint64(n))
}

// Set n to the counter.
func (m *Counter) Set(n uint64) {
	atomic.StoreUint64(&m.n, n)
}

// Get returns counter's value.
func (m *Counter) Get() uint64 {
	return atomic.LoadUint64(&m.n)
}

func (m *Counter) IsEmpty() bool {
	return m.Get() == 0
}

func (m *Counter) WriteJSON(w io.Writer, _ string) {
	fmt.Fprintf(w, "%d", m.Get())
}

func (m *Counter) WritePrometheus(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, m.Get())
}

// NewCounter creates new Counter with the given name.
func NewCounter(name string) *Counter {
	m := &Counter{}
	registerMetric(name, m)
	return m
}
