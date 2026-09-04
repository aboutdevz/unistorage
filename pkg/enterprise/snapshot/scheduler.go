package snapshot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JobConfig defines an automated snapshot backup policy.
type JobConfig struct {
	JobID          string `json:"job_id"`
	Name           string `json:"name,omitempty"`
	Enabled        bool   `json:"enabled"`
	Schedule       string `json:"schedule"` // Cron expression
	SourceRemote   string `json:"source_remote"`
	SourcePath     string `json:"source_path"`
	DestRemote     string `json:"dest_remote"`
	DestPath       string `json:"dest_path"`
	RetentionLimit int    `json:"retention_limit"`
	UseChecksum    bool   `json:"use_checksum"`
	TimeoutMinutes int    `json:"timeout_minutes"`
}

// CronSchedule represents parsed 5-field cron matchers.
type CronSchedule struct {
	raw     string
	minutes map[int]bool
	hours   map[int]bool
	doms    map[int]bool
	months  map[int]bool
	dows    map[int]bool
}

// ParseCron parses a 5-field cron expression or macro.
func ParseCron(expr string) (*CronSchedule, error) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "@hourly":
		expr = "0 * * * *"
	case "@daily":
		expr = "0 0 * * *"
	case "@weekly":
		expr = "0 0 * * 0"
	case "@monthly":
		expr = "0 0 1 * *"
	case "@yearly", "@annually":
		expr = "0 0 1 1 *"
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("invalid cron expression: expected 5 fields, got %d", len(fields))
	}

	minutes, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("invalid minute field '%s': %w", fields[0], err)
	}

	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("invalid hour field '%s': %w", fields[1], err)
	}

	doms, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("invalid day-of-month field '%s': %w", fields[2], err)
	}

	months, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("invalid month field '%s': %w", fields[3], err)
	}

	dows, err := parseCronField(fields[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("invalid day-of-week field '%s': %w", fields[4], err)
	}
	// Day 7 is also Sunday in standard cron
	if dows[7] {
		dows[0] = true
	}

	return &CronSchedule{
		raw:     expr,
		minutes: minutes,
		hours:   hours,
		doms:    doms,
		months:  months,
		dows:    dows,
	}, nil
}

func parseCronField(field string, min, max int) (map[int]bool, error) {
	result := make(map[int]bool)
	parts := strings.Split(field, ",")
	for _, part := range parts {
		step := 1
		rangeStr := part
		if strings.Contains(part, "/") {
			subParts := strings.Split(part, "/")
			if len(subParts) != 2 {
				return nil, fmt.Errorf("invalid step syntax")
			}
			rangeStr = subParts[0]
			s, err := strconv.Atoi(subParts[1])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid step value: %s", subParts[1])
			}
			step = s
		}

		var start, end int
		if rangeStr == "*" {
			start = min
			end = max
		} else if strings.Contains(rangeStr, "-") {
			rangeParts := strings.Split(rangeStr, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range syntax")
			}
			s, err1 := strconv.Atoi(rangeParts[0])
			e, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || s < min || e > max || s > e {
				return nil, fmt.Errorf("invalid range bounds: %s", rangeStr)
			}
			start = s
			end = e
		} else {
			val, err := strconv.Atoi(rangeStr)
			if err != nil || val < min || val > max {
				return nil, fmt.Errorf("invalid value: %s", rangeStr)
			}
			start = val
			end = val
		}

		for i := start; i <= end; i += step {
			result[i] = true
		}
	}
	return result, nil
}

// Matches returns true if the time matches the cron schedule.
func (cs *CronSchedule) Matches(t time.Time) bool {
	t = t.UTC()
	if !cs.minutes[t.Minute()] {
		return false
	}
	if !cs.hours[t.Hour()] {
		return false
	}
	if !cs.doms[t.Day()] {
		return false
	}
	if !cs.months[int(t.Month())] {
		return false
	}
	if !cs.dows[int(t.Weekday())] {
		return false
	}
	return true
}

// Next finds the next time after `from` matching this cron schedule.
func (cs *CronSchedule) Next(from time.Time) time.Time {
	// Truncate to next minute
	t := from.UTC().Truncate(time.Minute).Add(time.Minute)
	// Search up to 5 years ahead
	limit := t.Add(5 * 365 * 24 * time.Hour)
	for t.Before(limit) {
		if cs.Matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// JobRunner is the execution function invoked when a scheduled job triggers.
type JobRunner func(ctx context.Context, job JobConfig) error

// Scheduler manages cron backup schedules.
type Scheduler struct {
	mu           sync.RWMutex
	jobs         map[string]JobConfig
	schedules    map[string]*CronSchedule
	runner       JobRunner
	tickDuration time.Duration
	stopCh       chan struct{}
	running      bool
}

// NewScheduler constructs a snapshot scheduler.
func NewScheduler(runner JobRunner) *Scheduler {
	return &Scheduler{
		jobs:         make(map[string]JobConfig),
		schedules:    make(map[string]*CronSchedule),
		runner:       runner,
		tickDuration: time.Minute,
		stopCh:       make(chan struct{}),
	}
}

// SetTickDuration overrides the tick interval (useful for high-speed testing).
func (s *Scheduler) SetTickDuration(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickDuration = d
}

// AddJob registers or updates a backup policy.
func (s *Scheduler) AddJob(job JobConfig) error {
	if job.JobID == "" {
		return fmt.Errorf("job_id cannot be empty")
	}
	cronSched, err := ParseCron(job.Schedule)
	if err != nil {
		return fmt.Errorf("invalid schedule for job %s: %w", job.JobID, err)
	}
	if job.TimeoutMinutes <= 0 {
		job.TimeoutMinutes = 60
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.JobID] = job
	s.schedules[job.JobID] = cronSched
	return nil
}

// RemoveJob removes a backup policy.
func (s *Scheduler) RemoveJob(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, jobID)
	delete(s.schedules, jobID)
}

// GetJob retrieves a job config by ID.
func (s *Scheduler) GetJob(jobID string) (JobConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[jobID]
	return job, ok
}

// ListJobs returns all registered jobs.
func (s *Scheduler) ListJobs() []JobConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]JobConfig, 0, len(s.jobs))
	for _, j := range s.jobs {
		list = append(list, j)
	}
	return list
}

// Start runs the background scheduling loop.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	s.running = true
	stopCh := make(chan struct{})
	s.stopCh = stopCh
	tickDur := s.tickDuration
	s.mu.Unlock()

	ticker := time.NewTicker(tickDur)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case now := <-ticker.C:
				s.evaluate(ctx, now)
			}
		}
	}()

	return nil
}

// Stop terminates the scheduler tick loop.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	s.running = false
}

func (s *Scheduler) evaluate(ctx context.Context, now time.Time) {
	s.mu.RLock()
	type runnable struct {
		job JobConfig
	}
	var toRun []runnable
	for jobID, job := range s.jobs {
		if !job.Enabled {
			continue
		}
		sched := s.schedules[jobID]
		if sched != nil && sched.Matches(now) {
			toRun = append(toRun, runnable{job: job})
		}
	}
	runner := s.runner
	s.mu.RUnlock()

	if runner == nil {
		return
	}

	for _, r := range toRun {
		job := r.job
		go func(j JobConfig) {
			timeout := time.Duration(j.TimeoutMinutes) * time.Minute
			jobCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			_ = runner(jobCtx, j)
		}(job)
	}
}

// TriggerJob executes a specific job immediately outside its regular cron schedule.
func (s *Scheduler) TriggerJob(ctx context.Context, jobID string) error {
	s.mu.RLock()
	job, exists := s.jobs[jobID]
	runner := s.runner
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}
	if runner == nil {
		return fmt.Errorf("no runner configured on scheduler")
	}

	timeout := time.Duration(job.TimeoutMinutes) * time.Minute
	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return runner(jobCtx, job)
}
