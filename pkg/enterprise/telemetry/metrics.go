package telemetry

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MetricType represents Prometheus metric types.
type MetricType string

const (
	MetricTypeGauge   MetricType = "gauge"
	MetricTypeCounter MetricType = "counter"
)

type metricValue struct {
	labels map[string]string
	value  float64
}

type metricFamily struct {
	name   string
	help   string
	mtype  MetricType
	values map[string]metricValue
}

// MetricsRegistry manages telemetry metrics for Prometheus exposition.
type MetricsRegistry struct {
	mu       sync.RWMutex
	families map[string]*metricFamily
}

// NewMetricsRegistry initializes a registry with standard UniStorage enterprise metrics.
func NewMetricsRegistry() *MetricsRegistry {
	r := &MetricsRegistry{
		families: make(map[string]*metricFamily),
	}

	r.registerFamily("unistorage_disk_total_bytes", "Total capacity of inspected storage filesystem", MetricTypeGauge)
	r.registerFamily("unistorage_disk_free_bytes", "Free bytes available on storage filesystem", MetricTypeGauge)
	r.registerFamily("unistorage_disk_used_percent", "Percentage of disk space consumed (0 - 100)", MetricTypeGauge)
	r.registerFamily("unistorage_s3_up", "Reachability status of S3 backend (1=Up, 0=Down)", MetricTypeGauge)
	r.registerFamily("unistorage_s3_latency_seconds", "Round-trip latency for S3 probe", MetricTypeGauge)
	r.registerFamily("unistorage_transfers_total", "Total file transfers processed", MetricTypeCounter)
	r.registerFamily("unistorage_transfer_bytes_total", "Total volume of data transferred in bytes", MetricTypeCounter)
	r.registerFamily("unistorage_backup_runs_total", "Total snapshot backup executions", MetricTypeCounter)
	r.registerFamily("unistorage_backup_skipped_overlap_total", "Count of backup executions skipped by mutex", MetricTypeCounter)
	r.registerFamily("unistorage_retention_pruned_total", "Number of expired snapshots deleted", MetricTypeCounter)
	r.registerFamily("unistorage_alerts_dispatched_total", "Count of webhook alert notifications dispatched", MetricTypeCounter)

	return r
}

func (r *MetricsRegistry) registerFamily(name, help string, mtype MetricType) {
	r.families[name] = &metricFamily{
		name:   name,
		help:   help,
		mtype:  mtype,
		values: make(map[string]metricValue),
	}
}

func labelsKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(labels[k])
	}
	return sb.String()
}

// SetGauge sets the value of a gauge metric.
func (r *MetricsRegistry) SetGauge(name string, value float64, labels map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fam, exists := r.families[name]
	if !exists {
		fam = &metricFamily{
			name:   name,
			help:   name,
			mtype:  MetricTypeGauge,
			values: make(map[string]metricValue),
		}
		r.families[name] = fam
	}

	key := labelsKey(labels)
	fam.values[key] = metricValue{
		labels: cloneLabels(labels),
		value:  value,
	}
}

// IncCounter increments a counter metric by delta.
func (r *MetricsRegistry) IncCounter(name string, delta float64, labels map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fam, exists := r.families[name]
	if !exists {
		fam = &metricFamily{
			name:   name,
			help:   name,
			mtype:  MetricTypeCounter,
			values: make(map[string]metricValue),
		}
		r.families[name] = fam
	}

	key := labelsKey(labels)
	cur := fam.values[key]
	fam.values[key] = metricValue{
		labels: cloneLabels(labels),
		value:  cur.value + delta,
	}
}

// SetDiskMetrics updates filesystem disk metrics.
func (r *MetricsRegistry) SetDiskMetrics(u *DiskUsage) {
	if u == nil {
		return
	}
	labels := map[string]string{"path": u.Path}
	r.SetGauge("unistorage_disk_total_bytes", float64(u.TotalBytes), labels)
	r.SetGauge("unistorage_disk_free_bytes", float64(u.FreeBytes), labels)
	r.SetGauge("unistorage_disk_used_percent", u.UsedPercent, labels)
}

// SetS3ProbeMetrics updates S3 probe metrics.
func (r *MetricsRegistry) SetS3ProbeMetrics(res ProbeResult) {
	labels := map[string]string{"remote": res.Remote, "bucket": res.Bucket}
	upVal := 0.0
	if res.Up {
		upVal = 1.0
	}
	r.SetGauge("unistorage_s3_up", upVal, labels)
	r.SetGauge("unistorage_s3_latency_seconds", res.LatencySeconds, labels)
}

// IncTransfers records a file transfer.
func (r *MetricsRegistry) IncTransfers(direction, status string, count int64) {
	r.IncCounter("unistorage_transfers_total", float64(count), map[string]string{
		"direction": direction,
		"status":    status,
	})
}

// AddTransferBytes records transferred bytes.
func (r *MetricsRegistry) AddTransferBytes(direction string, bytes int64) {
	r.IncCounter("unistorage_transfer_bytes_total", float64(bytes), map[string]string{
		"direction": direction,
	})
}

// IncBackupRuns records a backup run outcome.
func (r *MetricsRegistry) IncBackupRuns(job, status string, count int64) {
	r.IncCounter("unistorage_backup_runs_total", float64(count), map[string]string{
		"job":    job,
		"status": status,
	})
}

// IncBackupSkippedOverlap records skipped overlap.
func (r *MetricsRegistry) IncBackupSkippedOverlap(job string) {
	r.IncCounter("unistorage_backup_skipped_overlap_total", 1, map[string]string{
		"job": job,
	})
}

// IncRetentionPruned records pruned snapshots.
func (r *MetricsRegistry) IncRetentionPruned(job string, count int64) {
	r.IncCounter("unistorage_retention_pruned_total", float64(count), map[string]string{
		"job": job,
	})
}

// IncAlertsDispatched records a dispatched webhook alert.
func (r *MetricsRegistry) IncAlertsDispatched(severity, target string) {
	r.IncCounter("unistorage_alerts_dispatched_total", 1, map[string]string{
		"severity": severity,
		"target":   target,
	})
}

// Format returns the standard Prometheus text exposition format.
func (r *MetricsRegistry) Format() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	famNames := make([]string, 0, len(r.families))
	for name := range r.families {
		famNames = append(famNames, name)
	}
	sort.Strings(famNames)

	var sb strings.Builder
	for _, name := range famNames {
		fam := r.families[name]
		if len(fam.values) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", fam.name, fam.help))
		sb.WriteString(fmt.Sprintf("# TYPE %s %s\n", fam.name, fam.mtype))

		// Sort value keys for deterministic output
		vkeys := make([]string, 0, len(fam.values))
		for k := range fam.values {
			vkeys = append(vkeys, k)
		}
		sort.Strings(vkeys)

		for _, k := range vkeys {
			mv := fam.values[k]
			sb.WriteString(fam.name)
			if len(mv.labels) > 0 {
				sb.WriteString("{")
				lkeys := make([]string, 0, len(mv.labels))
				for lk := range mv.labels {
					lkeys = append(lkeys, lk)
				}
				sort.Strings(lkeys)
				for i, lk := range lkeys {
					if i > 0 {
						sb.WriteString(",")
					}
					escapedVal := strings.ReplaceAll(mv.labels[lk], "\\", "\\\\")
					escapedVal = strings.ReplaceAll(escapedVal, "\"", "\\\"")
					escapedVal = strings.ReplaceAll(escapedVal, "\n", "\\n")
					sb.WriteString(fmt.Sprintf("%s=\"%s\"", lk, escapedVal))
				}
				sb.WriteString("}")
			}
			valStr := strconv.FormatFloat(mv.value, 'f', -1, 64)
			sb.WriteString(fmt.Sprintf(" %s\n", valStr))
		}
	}

	return sb.String()
}

// Handler returns an http.Handler that serves the Prometheus metrics exposition.
func (r *MetricsRegistry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Format()))
	})
}

func cloneLabels(in map[string]string) map[string]string {
	if in == nil {
		return make(map[string]string)
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
