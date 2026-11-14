package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConfiguredSupportIsNotProviderAvailability(t *testing.T) {
	if v, err := New("", "", "", nil); err != nil || v != nil {
		t.Fatal("unconfigured server advertised a verifier", err)
	}
	for _, keys := range [][2]string{{"site", ""}, {"", "secret"}, {"site key", "secret"}, {"site", "\nsecret"}, {strings.Repeat("s", 257), "secret"}} {
		if _, err := New(keys[0], keys[1], "control.example.test", nil); !errors.Is(err, ErrConfiguration) {
			t.Fatal("partial or invalid key configuration was accepted", err)
		}
	}
	v, err := New("public-site", "private-secret", "control.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("provider outage")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), "widget-response", "cha_"+strings.Repeat("A", 22), time.Now()); !errors.Is(err, ErrUnavailable) || v.SiteKey != "public-site" {
		t.Fatal("outage silently changed the configured capability", err)
	}
}

func TestSiteverifyChecksExactAttemptAndControlPage(t *testing.T) {
	now := time.Now().UTC()
	attempt := "cha_" + strings.Repeat("A", 22)
	valid := map[string]any{"success": true, "hostname": "control.example.test", "action": Action, "cdata": attempt, "challenge_ts": now.Format(time.RFC3339Nano)}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   error
	}{
		{"valid", func(map[string]any) {}, nil},
		{"another hostname", func(r map[string]any) { r["hostname"] = "app.example.test" }, ErrRejected},
		{"another action", func(r map[string]any) { r["action"] = "login" }, ErrRejected},
		{"another attempt", func(r map[string]any) { r["cdata"] = "cha_" + strings.Repeat("B", 22) }, ErrRejected},
		{"too old", func(r map[string]any) {
			r["challenge_ts"] = now.Add(-5*time.Minute - time.Second).Format(time.RFC3339Nano)
		}, ErrRejected},
		{"future", func(r map[string]any) { r["challenge_ts"] = now.Add(6 * time.Second).Format(time.RFC3339Nano) }, ErrRejected},
		{"missing time", func(r map[string]any) { delete(r, "challenge_ts") }, ErrRejected},
		{"unsuccessful", func(r map[string]any) { r["success"] = false }, ErrRejected},
		{"internal error", func(r map[string]any) { r["success"] = false; r["error-codes"] = []string{"internal-error"} }, ErrUnavailable},
		{"bad operator secret", func(r map[string]any) { r["success"] = false; r["error-codes"] = []string{"invalid-input-secret"} }, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := make(map[string]any, len(valid))
			for key, value := range valid {
				result[key] = value
			}
			tc.change(result)
			raw, _ := json.Marshal(result)
			var calls int
			v, err := New("public-site", "private-secret", "control.example.test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(r.Body)
				form, parseErr := url.ParseQuery(string(body))
				if err != nil || parseErr != nil || r.URL.String() != endpoint || r.Method != http.MethodPost ||
					form.Get("secret") != "private-secret" || form.Get("response") != "widget-response" || len(form) != 2 ||
					r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("Siteverify request lost its fixed endpoint or bounded credential fields")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			proof, err := v.Verify(t.Context(), "widget-response", attempt, now)
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatal("Siteverify result lost its classification", err, tc.want, calls)
			}
			if (proof.ID() == attempt) != (tc.want == nil) {
				t.Fatal("verification proof did not match the successful attempt")
			}
		})
	}
}

func TestSiteverifyBoundsInputsResponseAndLifetime(t *testing.T) {
	attempt := "cha_" + strings.Repeat("A", 22)
	for _, body := range []string{"not JSON", strings.Repeat(" ", (64<<10)+1)} {
		calls := 0
		v, err := New("site", "secret", "control.example.test", &http.Client{Timeout: time.Minute, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		if v.client.Timeout != 2*time.Second || v.client.Jar != nil || v.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Fatal("provider exchange lost its fixed deadline or redirect boundary")
		}
		for _, input := range []struct{ token, attempt string }{{"", attempt}, {strings.Repeat("t", 2049), attempt}, {"token", "not-an-attempt"}} {
			if _, err := v.Verify(t.Context(), input.token, input.attempt, time.Now()); !errors.Is(err, ErrRejected) || calls != 0 {
				t.Fatal("invalid input contacted the provider", err)
			}
		}
		if _, err := v.Verify(t.Context(), "token", attempt, time.Now()); !errors.Is(err, ErrUnavailable) {
			t.Fatal("malformed or oversized provider response was accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	v, _ := New("site", "secret", "control.example.test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })})
	if _, err := v.Verify(ctx, "token", attempt, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled verification did not fail closed", err)
	}
}
