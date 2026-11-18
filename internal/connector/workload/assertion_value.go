package workload

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrAssertionUnavailable = errors.New("workload assertion is unavailable")

// AcquireAssertion reads one proof from the caller's request-scoped source and
// verifies its wire bounds. the control authority verifies the proof itself.
func AcquireAssertion(ctx context.Context, source func(context.Context) (string, error)) (string, error) {
	if ctx.Err() != nil {
		return "", context.Cause(ctx)
	}
	if source == nil {
		return "", ErrAssertionUnavailable
	}
	raw, err := source(ctx)
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", context.Cause(ctx)
	}
	return boundedAssertion(raw)
}

func boundedAssertion(raw string) (string, error) {
	space := func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' }
	raw = strings.TrimFunc(raw, space)
	if raw == "" || len(raw) > 32<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) || strings.ContainsFunc(raw, space) {
		return "", ErrAssertionUnavailable
	}
	return raw, nil
}
