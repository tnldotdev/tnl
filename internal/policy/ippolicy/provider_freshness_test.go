package ippolicy

import (
	"net/http"
	"testing"
	"time"
)

func TestProviderWindowSpendsLatencyAcrossIndependentClocks(t *testing.T) {
	control := time.Date(2038, 1, 2, 3, 4, 5, 0, time.UTC)
	local := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	window := NewProviderWindow(control.Add(-24*time.Hour+time.Minute), control)
	checked, fresh, until, err := window.Local(local, local.Add(59*time.Second))
	if err != nil || !until.Equal(local.Add(time.Minute)) || !checked.Add(ProviderLastGoodFor).Equal(until) ||
		!fresh.Equal(checked.Add(ProviderFreshFor)) {
		t.Fatal("provider expiry used the client's interpretation of control time or response arrival", checked, fresh, until, err)
	}
	if _, _, _, err := window.Local(local, local.Add(time.Minute)); err == nil {
		t.Fatal("late response revived an actually expired provider policy")
	}
	headers := make(http.Header)
	window.WriteHeaders(headers)
	if read, err := ReadProviderWindow(headers); err != nil || read != window {
		t.Fatal("provider window headers changed authority", read, err)
	}
	for _, mutate := range []func(http.Header){
		func(h http.Header) { h.Del("TNL-Webhook-Policy-Observed-At") },
		func(h http.Header) {
			h.Set("TNL-Webhook-Policy-Checked-At", control.Add(time.Second).Format(time.RFC3339Nano))
		},
		func(h http.Header) {
			h.Set("TNL-Webhook-Policy-Fresh-Until", control.Add(time.Hour).Format(time.RFC3339Nano))
		},
		func(h http.Header) {
			h.Set("TNL-Webhook-Policy-Valid-Until", control.Add(25*time.Hour).Format(time.RFC3339Nano))
		},
	} {
		invalid := headers.Clone()
		mutate(invalid)
		if _, err := ReadProviderWindow(invalid); err == nil {
			t.Error("invalid provider window widened source authority", invalid)
		}
	}
}
