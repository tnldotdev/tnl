package authorityclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestResponseBoundariesAndBodyOwnership(t *testing.T) {
	for _, test := range []struct {
		name, payload          string
		status                 int
		wantError, unavailable bool
	}{
		{"empty", "", 204, false, false},
		{"numbers", `{"value":9007199254740993}`, 200, false, false},
		{"unknown", `{"other":1}`, 200, true, false},
		{"trailing", `{} {}`, 200, true, false},
		{"oversized", strings.Repeat(" ", maxResponseBytes+1), 200, true, false},
		{"malformed rate limit", `not JSON`, 429, true, false},
		{"malformed unavailable", `not JSON`, 503, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &responseBody{Reader: strings.NewReader(test.payload)}
			result, err := request[struct {
				Value any `json:"value"`
			}](t.Context(), &Client{timeout: time.Second}, func(context.Context, ...authorityv1.RequestEditorFn) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: body}, nil
			})
			if !body.closed || (err != nil) != test.wantError || errors.Is(err, ErrUnavailable) != test.unavailable {
				t.Fatalf("closed=%v, error=%v", body.closed, err)
			}
			if test.name == "numbers" && result.Value != json.Number("9007199254740993") {
				t.Fatalf("number = %#v", result.Value)
			}
			if test.status == 429 && !errors.Is(err, ErrRateLimited) {
				t.Fatalf("rate limit = %v", err)
			}
		})
	}
	failure := errors.New("read failure")
	body := &responseBody{Reader: iotest.ErrReader(failure)}
	_, err := request[struct{}](t.Context(), &Client{timeout: time.Second}, func(context.Context, ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body}, nil
	})
	if !body.closed || !errors.Is(err, ErrUnavailable) || !errors.Is(err, failure) {
		t.Fatalf("read failure = %v, closed=%v", err, body.closed)
	}
}

type responseBody struct {
	io.Reader
	closed bool
}

func (b *responseBody) Close() error { b.closed = true; return nil }
