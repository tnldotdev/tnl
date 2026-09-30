package certificates

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/workerloop"
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
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: operationTimeout,
		IdleInterval:     idleInterval,
		Process:          worker.processOne,
		OnError: func(err error) {
			if !errors.Is(err, context.Canceled) {
				logger.Error(failureMessage, "error", err)
			}
		},
	})
}

func pollAt(now time.Time, interval time.Duration, retryAfter time.Time) time.Time {
	result := now.Add(interval)
	if retryAfter.After(result) {
		return retryAfter.UTC()
	}
	return result
}

// acmeOrderProgress translates the ca's status into the next local issuance
// stage. callers own their stored state and any stage-specific side effects.
func acmeOrderProgress(status string, now, retryAfter time.Time, interval time.Duration) (controlstate.ACMEOrderState, time.Time, error) {
	switch status {
	case "pending":
		return controlstate.ACMEOrderAuthorizing, pollAt(now, interval, retryAfter), nil
	case "ready":
		return controlstate.ACMEOrderReadyToFinalize, now, nil
	case "processing":
		return controlstate.ACMEOrderFinalizing, pollAt(now, interval, retryAfter), nil
	case "valid":
		return controlstate.ACMEOrderFinalizing, now, nil
	case "invalid":
		return "", time.Time{}, terminalf("ACME order became invalid")
	default:
		return "", time.Time{}, fmt.Errorf("certificates: unknown ACME order status %q", status)
	}
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
