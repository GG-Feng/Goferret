// Fixture for v3 rule R1 (hand-written; not taken from any evaluated project).
package fixture

import (
	"encoding/binary"
	"net/http"
	"strconv"
)

// unbounded: count parsed from a request header decides an allocation size and an index.
func Unbounded(r *http.Request) []string {
	n, _ := strconv.Atoi(r.Header.Get("X-Count"))
	parts := make([]string, n)
	idx, _ := strconv.Atoi(r.URL.Query().Get("i"))
	parts[idx-1] = "x"
	return parts
}

// bounded: the same flow, with range checks between parse and use.
func Bounded(r *http.Request) []string {
	n, _ := strconv.Atoi(r.Header.Get("X-Count"))
	if n < 1 || n > 32 {
		return nil
	}
	parts := make([]string, n)
	idx, _ := strconv.Atoi(r.URL.Query().Get("i"))
	if idx < 1 || idx > n {
		return nil
	}
	parts[idx-1] = "x"
	return parts
}

// derived: size computed from a parsed length prefix.
func Derived(b []byte) []byte {
	l := binary.BigEndian.Uint32(b[:4])
	total := int(l) + 4
	return make([]byte, total)
}

// unrelated: constant sizes and range-loop indexes are not tracked.
func Unrelated(xs []int) []int {
	out := make([]int, 0, 8)
	for i := range xs {
		out = append(out, xs[i])
	}
	return out
}
