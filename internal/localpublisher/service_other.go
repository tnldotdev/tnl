//go:build !linux && !darwin

package localpublisher

import (
	"context"
	"errors"
)

func activateService(context.Context) error {
	return errors.New("publisher service needs macOS or Linux")
}
