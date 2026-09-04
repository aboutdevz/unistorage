package s3

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/aws/smithy-go"
)

// RetryConfig holds exponential backoff parameters.
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

// DefaultRetryConfig returns standard retry settings: 5 retries, 100ms base, 5s max.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 5,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   5 * time.Second,
	}
}

// IsTransient checks whether an error is temporary and can be retried.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	// Context cancellation or deadline exceeded are not retryable
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check net.Error
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Check connection resets and EOFs
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	// Check AWS API errors
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch code {
		case "RequestTimeout", "RequestTimeoutException", "SlowDown", "TooManyRequestsException",
			"InternalError", "ServiceUnavailable", "500", "502", "503", "504":
			return true
		case "NoSuchBucket", "NoSuchKey", "NotFound", "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch":
			return false
		}
	}

	// String checking fallback for HTTP status codes or message patterns
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "slowdown") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "503") ||
		strings.Contains(msg, "502") ||
		strings.Contains(msg, "504") ||
		strings.Contains(msg, "timeout") {
		return true
	}

	return false
}

// ExecuteWithRetry executes an operation with exponential backoff and full jitter.
func ExecuteWithRetry(ctx context.Context, cfg RetryConfig, op func() error) error {
	var err error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		err = op()
		if err == nil {
			return nil
		}

		if !IsTransient(err) || attempt == cfg.MaxRetries {
			return err
		}

		// Exponential backoff calculation: min(MaxDelay, BaseDelay * 2^attempt)
		multiplier := math.Pow(2, float64(attempt))
		backoff := math.Min(float64(cfg.MaxDelay), float64(cfg.BaseDelay)*multiplier)

		// Full jitter: random sleep between 0 and backoff
		jitteredSleep := time.Duration(rand.Float64() * backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitteredSleep):
		}
	}
	return err
}
