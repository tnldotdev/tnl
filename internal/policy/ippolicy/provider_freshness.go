package ippolicy

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
)

const (
	ProviderFreshFor    = 15 * time.Minute
	ProviderLastGoodFor = 24 * time.Hour
)

// ProviderWindow carries the catalog's own observation and last successful
// provider check. a client confirmation cannot restart the last-good allowance.
type ProviderWindow struct {
	ObservedAt, CheckedAt, FreshUntil, ValidUntil time.Time
}

func NewProviderWindow(checkedAt, observedAt time.Time) ProviderWindow {
	return ProviderWindow{ObservedAt: observedAt, CheckedAt: checkedAt,
		FreshUntil: checkedAt.Add(ProviderFreshFor), ValidUntil: checkedAt.Add(ProviderLastGoodFor)}
}

func (w ProviderWindow) Valid() bool {
	return !w.CheckedAt.IsZero() && !w.ObservedAt.Before(w.CheckedAt) &&
		w.FreshUntil.Equal(w.CheckedAt.Add(ProviderFreshFor)) &&
		w.ValidUntil.Equal(w.CheckedAt.Add(ProviderLastGoodFor)) && w.ObservedAt.Before(w.ValidUntil)
}

func (w ProviderWindow) WriteHeaders(headers http.Header) {
	headers.Set("TNL-Webhook-Policy-Observed-At", w.ObservedAt.Format(time.RFC3339Nano))
	headers.Set("TNL-Webhook-Policy-Checked-At", w.CheckedAt.Format(time.RFC3339Nano))
	headers.Set("TNL-Webhook-Policy-Fresh-Until", w.FreshUntil.Format(time.RFC3339Nano))
	headers.Set("TNL-Webhook-Policy-Valid-Until", w.ValidUntil.Format(time.RFC3339Nano))
}

func ReadProviderWindow(headers http.Header) (ProviderWindow, error) {
	var w ProviderWindow
	for _, field := range []struct {
		header string
		value  *time.Time
	}{
		{"TNL-Webhook-Policy-Observed-At", &w.ObservedAt},
		{"TNL-Webhook-Policy-Checked-At", &w.CheckedAt},
		{"TNL-Webhook-Policy-Fresh-Until", &w.FreshUntil},
		{"TNL-Webhook-Policy-Valid-Until", &w.ValidUntil},
	} {
		value, err := time.Parse(time.RFC3339Nano, headers.Get(field.header))
		if err != nil {
			return ProviderWindow{}, ErrInvalidPolicy
		}
		*field.value = value
	}
	if !w.Valid() {
		return ProviderWindow{}, ErrInvalidPolicy
	}
	return w, nil
}

// Local anchors the remaining server allowance to request start, not response
// arrival or the client's wall-clock interpretation of a server timestamp.
func (w ProviderWindow) Local(startedAt, now time.Time) (checkedAt, freshUntil, validUntil time.Time, err error) {
	if !w.Valid() {
		return time.Time{}, time.Time{}, time.Time{}, ErrInvalidPolicy
	}
	validUntil, err = controloutage.LocalDeadline(startedAt, w.ObservedAt, w.ValidUntil, now)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	checkedAt = validUntil.Add(-ProviderLastGoodFor)
	freshUntil = checkedAt.Add(ProviderFreshFor)
	return checkedAt, freshUntil, validUntil, nil
}
