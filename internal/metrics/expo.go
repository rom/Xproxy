// Package metrics provides Prometheus text exposition without a client
// library, a lock-free histogram, and a ring buffer of sampled time series
// for graphs (docs/AMR.md, AMR-026).
package metrics

import (
	"bufio"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Encoder writes the Prometheus text format (version 0.0.4). Metric
// families are written in the order their first sample is added; samples of
// one family must be added together.
type Encoder struct {
	w       *bufio.Writer
	current string
	err     error
}

// NewEncoder wraps w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: bufio.NewWriterSize(w, 32<<10)}
}

// Labels is a set of label pairs. Keys are sorted on output.
type Labels map[string]string

func (e *Encoder) family(name, typ, help string) {
	if e.current == name {
		return
	}
	e.current = name
	_, _ = e.w.WriteString("# HELP ")
	_, _ = e.w.WriteString(name)
	_ = e.w.WriteByte(' ')
	_, _ = e.w.WriteString(escapeHelp(help))
	_, _ = e.w.WriteString("\n# TYPE ")
	_, _ = e.w.WriteString(name)
	_ = e.w.WriteByte(' ')
	_, _ = e.w.WriteString(typ)
	_ = e.w.WriteByte('\n')
}

func (e *Encoder) sample(name string, labels Labels, value float64) {
	_, _ = e.w.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		_ = e.w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				_ = e.w.WriteByte(',')
			}
			_, _ = e.w.WriteString(k)
			_, _ = e.w.WriteString(`="`)
			_, _ = e.w.WriteString(escapeLabel(labels[k]))
			_ = e.w.WriteByte('"')
		}
		_ = e.w.WriteByte('}')
	}
	_ = e.w.WriteByte(' ')
	_, _ = e.w.WriteString(formatFloat(value))
	_ = e.w.WriteByte('\n')
}

// Counter adds a counter sample.
func (e *Encoder) Counter(name, help string, labels Labels, value float64) {
	e.family(name, "counter", help)
	e.sample(name, labels, value)
}

// Gauge adds a gauge sample.
func (e *Encoder) Gauge(name, help string, labels Labels, value float64) {
	e.family(name, "gauge", help)
	e.sample(name, labels, value)
}

// Histogram adds a histogram family from a Snapshot.
func (e *Encoder) Histogram(name, help string, labels Labels, h HistogramSnapshot) {
	e.family(name, "histogram", help)
	var cum uint64
	for i, b := range h.Bounds {
		cum += h.Counts[i]
		l := cloneLabels(labels)
		l["le"] = formatFloat(b)
		e.sample(name+"_bucket", l, float64(cum))
	}
	l := cloneLabels(labels)
	l["le"] = "+Inf"
	e.sample(name+"_bucket", l, float64(h.Count))
	e.sample(name+"_sum", labels, h.Sum)
	e.sample(name+"_count", labels, float64(h.Count))
}

// Flush writes buffered output.
func (e *Encoder) Flush() error {
	if err := e.w.Flush(); err != nil {
		return err
	}
	return e.err
}

func cloneLabels(l Labels) Labels {
	out := make(Labels, len(l)+1)
	for k, v := range l {
		out[k] = v
	}
	return out
}

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeHelp(s string) string {
	return strings.NewReplacer("\\", `\\`, "\n", `\n`).Replace(s)
}
