package http

// observeRoute records the outcome and the bytes of a request on its route.
func (cr *compiledRoute) observe(status int, denied bool, bytesIn, bytesOut int64) {
	if bytesIn > 0 {
		cr.bytesIn.Add(uint64(bytesIn)) //nolint:gosec // positive
	}
	if bytesOut > 0 {
		cr.bytesOut.Add(uint64(bytesOut)) //nolint:gosec // positive
	}
	switch {
	case denied:
		cr.counts[4].Add(1)
	case status >= 500:
		cr.counts[3].Add(1)
	case status >= 400:
		cr.counts[2].Add(1)
	case status >= 300:
		cr.counts[1].Add(1)
	default:
		cr.counts[0].Add(1)
	}
}

// routeClasses names the per route outcome buckets, in the order the
// counters are indexed.
var routeClasses = [...]string{"2xx", "3xx", "4xx", "5xx", "denied"}
