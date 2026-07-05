package certificates

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"
)

const (
	defaultLeaseDuration    = 2 * time.Minute
	defaultOperationTimeout = 30 * time.Second
	defaultPollInterval     = 2 * time.Second
	defaultIdleInterval     = 500 * time.Millisecond
)

type workerTiming struct {
	leaseDuration    time.Duration
	operationTimeout time.Duration
	pollInterval     time.Duration
	idleInterval     time.Duration
}

func workerTimingWithDefaults(leaseDuration, operationTimeout, pollInterval, idleInterval time.Duration) workerTiming {
	if leaseDuration <= 0 {
		leaseDuration = defaultLeaseDuration
	}
	if operationTimeout <= 0 {
		operationTimeout = defaultOperationTimeout
	}
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	if idleInterval <= 0 {
		idleInterval = defaultIdleInterval
	}
	return workerTiming{
		leaseDuration: leaseDuration, operationTimeout: operationTimeout,
		pollInterval: pollInterval, idleInterval: idleInterval,
	}
}

type loopWorker interface {
	processOne(context.Context) (bool, error)
}

func runWorkerLoop(
	ctx context.Context,
	worker loopWorker,
	logger *slog.Logger,
	operationTimeout, idleInterval time.Duration,
	failureMessage string,
) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		found, err := worker.processOne(operationCtx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error(failureMessage, "error", err)
		}
		delay := time.Duration(0)
		if !found || err != nil {
			delay = idleInterval
		}
		timer.Reset(delay)
	}
}

func pollAt(now time.Time, interval time.Duration, retryAfter time.Time) time.Time {
	result := now.Add(interval)
	if retryAfter.After(result) {
		return retryAfter.UTC()
	}
	return result
}

func truncateError(err error) string {
	value := err.Error()
	limit := min(len(value), 1024)
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

type terminalError struct{ message string }

func (e *terminalError) Error() string  { return e.message }
func (e *terminalError) Terminal() bool { return true }

func terminalf(format string, arguments ...any) error {
	return &terminalError{message: fmt.Sprintf("certificates: "+format, arguments...)}
}

func isTerminal(err error) bool {
	var terminal interface{ Terminal() bool }
	return errors.As(err, &terminal) && terminal.Terminal()
}
