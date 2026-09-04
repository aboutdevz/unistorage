package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// ProbeResult encapsulates reachability and performance metrics for a storage probe.
type ProbeResult struct {
	Remote              string        `json:"remote"`
	Bucket              string        `json:"bucket"`
	Up                  bool          `json:"up"`
	LatencySeconds      float64       `json:"latency_seconds"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	Error               error         `json:"error,omitempty"`
	Timestamp           time.Time     `json:"timestamp"`
	Duration            time.Duration `json:"-"`
}

// S3Probe monitors S3 endpoint availability and round-trip latency.
type S3Probe struct {
	mu                  sync.RWMutex
	consecutiveFailures map[string]int
	timeout             time.Duration
}

// NewS3Probe constructs an S3 probe with a specified per-probe timeout (default 5s).
func NewS3Probe(timeout time.Duration) *S3Probe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &S3Probe{
		consecutiveFailures: make(map[string]int),
		timeout:             timeout,
	}
}

// Probe executes a lightweight check against the storage driver and records latency and reachability.
func (p *S3Probe) Probe(ctx context.Context, driver storage.Driver, remote, bucket string) ProbeResult {
	probeKey := remote + "/" + bucket
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	start := time.Now()

	// Lightweight probe: List with empty/root prefix, or Stat root
	_, err := driver.List(probeCtx, "")
	duration := time.Since(start)
	latencySec := duration.Seconds()

	p.mu.Lock()
	defer p.mu.Unlock()

	res := ProbeResult{
		Remote:         remote,
		Bucket:         bucket,
		LatencySeconds: latencySec,
		Duration:       duration,
		Timestamp:      time.Now().UTC(),
	}

	if err != nil {
		p.consecutiveFailures[probeKey]++
		res.Up = false
		res.ConsecutiveFailures = p.consecutiveFailures[probeKey]
		res.Error = err
	} else {
		p.consecutiveFailures[probeKey] = 0
		res.Up = true
		res.ConsecutiveFailures = 0
	}

	return res
}

// GetConsecutiveFailures returns the current streak of failed probes for a target.
func (p *S3Probe) GetConsecutiveFailures(remote, bucket string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.consecutiveFailures[remote+"/"+bucket]
}

// Reset clears failure counts.
func (p *S3Probe) Reset(remote, bucket string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.consecutiveFailures, remote+"/"+bucket)
}
