package applicationlimits

import (
	"errors"
	"time"
)

const DefaultRequestBodyIdleTimeout = 30 * time.Second

// request body idleness counts only while the publisher is reading incoming
// bytes. omission selects the default; an explicit duration cannot disable it.
func RequestBodyIdleTimeout(value *string) (time.Duration, error) {
	if value == nil {
		return DefaultRequestBodyIdleTimeout, nil
	}
	duration, err := time.ParseDuration(*value)
	if err != nil || duration <= 0 {
		return 0, errors.New("request body idle timeout must be a positive Go duration")
	}
	return duration, nil
}
