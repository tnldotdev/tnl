package controlclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestResponseBoundariesAndBodyOwnership(t *testing.T) {
	for _, test := range []struct {
		name, payload string
		status        int
		wantError     bool
	}{
		{"empty", "", 204, false},
		{"empty body-bearing response", "", 200, true},
		{"null", `null`, 200, true},
		{"whitespace null", " \nnull\t", 200, true},
		{"numbers", `{"value":9007199254740993}`, 200, false},
		{"unknown", `{"other":1}`, 200, true},
		{"partial unknown", `{"value":1,"other":2}`, 200, true},
		{"malformed", `{"value":`, 200, true},
		{"trailing", `{} {}`, 200, true},
		{"trailing garbage", `{} broken`, 200, true},
		{"exact limit", `{}` + strings.Repeat(" ", maxResponseBytes-2), 200, false},
		{"oversized", strings.Repeat(" ", maxResponseBytes+1), 200, true},
		{"malformed rate limit", `not JSON`, 429, true},
		{"malformed unavailable", `not JSON`, 503, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &responseBody{Reader: strings.NewReader(test.payload)}
			result, err := request[struct {
				Value any `json:"value"`
			}](t.Context(), &Client{timeout: time.Second}, "", func(context.Context, ...controlv1.RequestEditorFn) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: body}, nil
			})
			if !body.closed || (err != nil) != test.wantError || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRateLimited) {
				t.Fatalf("closed=%v, error=%v", body.closed, err)
			}
			if test.name == "numbers" && result.Value != float64(9007199254740992) {
				t.Fatalf("number = %#v", result.Value)
			}
			if err != nil && result.Value != nil {
				t.Fatal("failure exposed a partially decoded result")
			}
		})
	}
	failure := errors.New("read failure")
	body := &responseBody{Reader: iotest.ErrReader(failure)}
	_, err := request[struct{}](t.Context(), &Client{timeout: time.Second}, "", func(context.Context, ...controlv1.RequestEditorFn) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body}, nil
	})
	if !body.closed || !errors.Is(err, ErrUnavailable) || !errors.Is(err, failure) {
		t.Fatalf("read failure = %v, closed=%v", err, body.closed)
	}
}

func TestResponseProblemPrecedenceAndRetryAfter(t *testing.T) {
	for _, test := range []struct {
		header string
		want   time.Duration
	}{
		{"", time.Second}, {"bad", time.Second}, {"-2", time.Second}, {"0", time.Second},
		{"7", 7 * time.Second}, {"999999", 24 * time.Hour}, {"9999999999999999999999", time.Second},
	} {
		t.Run(test.header, func(t *testing.T) {
			// unlike authorityclient, control classifies by problem code, not status.
			err := responseError(400, http.Header{"Retry-After": {test.header}}, []byte(`{"code":"rate_limited"}`))
			var rate *RateLimitError
			if !errors.As(err, &rate) || !errors.Is(err, ErrRateLimited) || rate.RetryAfter != test.want {
				t.Fatalf("rate limit error=%v", err)
			}
		})
	}
	for _, status := range []int{429, 503} {
		if err := responseError(status, nil, []byte(`{"code":"unauthenticated"}`)); !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRateLimited) {
			t.Fatalf("HTTP %d precedence=%v", status, err)
		}
	}
	if err := responseError(400, nil, []byte(`{"code":"unavailable"}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("problem mapping=%v", err)
	}
	if err := responseError(500, nil, []byte(`{"code":"internal"}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("internal problem mapping=%v", err)
	}
	if err := responseError(502, nil, []byte(`{"code":"forbidden"}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("valid 5xx problem mapping=%v", err)
	}
	if err := responseError(500, nil, []byte(`{"code":"future_code"}`)); errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown 5xx problem mapping=%v", err)
	}
}

type responseBody struct {
	io.Reader
	closed bool
}

func (b *responseBody) Close() error { b.closed = true; return nil }
