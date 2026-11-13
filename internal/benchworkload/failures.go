package benchworkload

import (
	"errors"
	"fmt"
	"slices"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

type measurementResponseError struct {
	operation string
	status    int
	code      diagnostic.Code
}

func (e *measurementResponseError) Error() string {
	if slices.Contains(diagnostic.Codes(), e.code) {
		return fmt.Sprintf("%s: status %d [%s]", e.operation, e.status, e.code)
	}
	return fmt.Sprintf("%s: status %d", e.operation, e.status)
}
func (*measurementResponseError) FailureReason() failure.Reason {
	return failure.LoadMeasurementFailed
}

func safeMeasurementFailure(err error) string {
	message := failure.SafeMessage(err, failure.LoadMeasurementFailed)
	var response *measurementResponseError
	if errors.As(err, &response) && response.status >= 100 && response.status <= 599 {
		message = response.Error() + "; " + message
	}
	return message
}
