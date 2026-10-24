package benchworkload

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/failure"
)

type measurementResponseError struct {
	operation string
	status    int
}

func (e *measurementResponseError) Error() string {
	return fmt.Sprintf("%s: status %d", e.operation, e.status)
}
func (*measurementResponseError) FailureReason() failure.Reason {
	return failure.BenchmarkMeasurementFailed
}

func safeMeasurementFailure(err error) string {
	message := failure.SafeMessage(err, failure.BenchmarkMeasurementFailed)
	var response *measurementResponseError
	if errors.As(err, &response) && response.status >= 100 && response.status <= 599 {
		message = response.Error() + "; " + message
	} else if errors.Is(err, io.EOF) {
		message = "connection ended before an HTTP response; " + message
	} else if errors.Is(err, io.ErrUnexpectedEOF) {
		message = "HTTP response ended early; " + message
	} else if errors.Is(err, context.DeadlineExceeded) {
		message = "request deadline expired; " + message
	}
	return message
}
