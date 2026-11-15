// Package metrics exposes a tiny, dependency-free Prometheus text endpoint and
// a health check for the opt-in loopback listener.
package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// New builds the metrics and health handler. Any probe may be nil; a nil probe
// reports zero. The listener is expected to be opt-in and loopback-only, but
// this handler itself is transport agnostic.
func New(active func() int64, total func() uint64, online func() int, dbBytes func() int64) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		var activeN int64
		if active != nil {
			activeN = active()
		}
		var totalN uint64
		if total != nil {
			totalN = total()
		}
		var onlineN int
		if online != nil {
			onlineN = online()
		}
		var dbN int64
		if dbBytes != nil {
			dbN = dbBytes()
		}

		var b strings.Builder
		writeMetric(&b, "hexline_sessions_active", "gauge",
			"Number of active sessions.", activeN)
		writeMetric(&b, "hexline_sessions_total", "counter",
			"Total number of sessions opened since process start.", totalN)
		writeMetric(&b, "hexline_online", "gauge",
			"Number of callers currently online.", onlineN)
		writeMetric(&b, "hexline_db_bytes", "gauge",
			"Approximate SQLite database size in bytes.", dbN)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(b.String()))
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("ok"))
		}
	})
	return mux
}

func writeMetric(b *strings.Builder, name, kind, help string, value any) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, escapeHelp(help))
	fmt.Fprintf(b, "# TYPE %s %s\n", name, kind)
	fmt.Fprintf(b, "%s %s\n", name, formatValue(value))
}

func formatValue(v any) string {
	switch n := v.(type) {
	case int:
		return strconv.FormatInt(int64(n), 10)
	case int64:
		return strconv.FormatInt(n, 10)
	case uint64:
		return strconv.FormatUint(n, 10)
	case float64:
		return strconv.FormatFloat(n, 'g', -1, 64)
	default:
		return "0"
	}
}

// escapeHelp escapes a HELP line per the Prometheus text exposition format.
func escapeHelp(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	return r.Replace(s)
}

// escapeLabelValue escapes a label value. The current metrics have no labels,
// but the helper is used whenever a labelled metric is added and is covered by
// tests so escaping cannot silently regress.
func escapeLabelValue(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}
