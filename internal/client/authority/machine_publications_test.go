package authority

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestMachinePublicationRequestsNeverUseConfiguredControlToken(t *testing.T) {
	var paths []string
	c, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("machine publication request used another credential")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("unbounded request")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if string(body["assertion"]) != `"explicit-proof"` {
			t.Fatal("explicit proof was not sent")
		}
		if strings.HasSuffix(r.URL.Path, "/cleanup") {
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"mps_session"}`))}, nil
	})}, "ambient-human-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeMachinePublication(t.Context(), authorityv1.MachinePublicationExchange{Assertion: "explicit-proof", Resource: "exact-resource", Nonce: "nonce", PublicKey: "public", Signature: "signature"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefreshMachinePublication(t.Context(), "mps_session", authorityv1.MachinePublicationRefresh{Assertion: "explicit-proof", Signature: "signature"}); err != nil {
		t.Fatal(err)
	}
	if err := c.CleanupMachinePublication(t.Context(), "mps_session", authorityv1.MachinePublicationCleanup{Assertion: "explicit-proof", InvocationId: "invocation"}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 || paths[0] != "/v1/machine-publication-sessions/exchange" || paths[1] != "/v1/machine-publication-sessions/mps_session/refresh" || paths[2] != "/v1/machine-publication-sessions/mps_session/cleanup" {
		t.Fatal("request did not use the canonical machine-publication contract")
	}
}

type machinePublicationFailingBody struct {
	fail   func() error
	reads  int
	closed bool
}

func (b *machinePublicationFailingBody) Read([]byte) (int, error) {
	b.reads++
	return 0, b.fail()
}

func (b *machinePublicationFailingBody) Close() error {
	b.closed = true
	return nil
}

func TestMachinePublicationHTTPCancellationPreservesIndependentFailure(t *testing.T) {
	for _, operation := range []string{"refresh", "cleanup"} {
		for _, boundary := range []string{"transport", "read"} {
			for _, cancellation := range []string{"canceled", "custom", "live"} {
				for _, independent := range []bool{false, true} {
					if cancellation == "live" && !independent {
						continue
					}
					name := operation + "/" + boundary + "/" + cancellation + "/cancellation-only"
					if independent {
						name = operation + "/" + boundary + "/" + cancellation + "/independent-failure"
					}
					t.Run(name, func(t *testing.T) {
						ctx, cancel := context.WithCancelCause(t.Context())
						defer cancel(nil)
						custom := errors.New("app stopped with a custom cause")
						sentinel := errors.New("independent HTTP boundary failure")
						fail := func() error {
							if cancellation == "live" {
								return sentinel
							}
							if cancellation == "custom" {
								cancel(custom)
							} else {
								cancel(nil)
							}
							if independent {
								return errors.Join(ctx.Err(), sentinel)
							}
							return ctx.Err()
						}
						body := &machinePublicationFailingBody{fail: fail}
						calls := 0
						const session = "mps_0123456789ABCDEFGHIJKL"
						client, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
							calls++
							defer r.Body.Close()
							if r.Method != "POST" || r.URL.Path != "/v1/machine-publication-sessions/"+session+"/"+operation || r.Header.Get("Authorization") != "" {
								t.Error("machine publication failure used another path or a control token")
							}
							if _, ok := r.Context().Deadline(); !ok {
								t.Error("unbounded authority request")
							}
							if boundary == "transport" {
								return nil, fail()
							}
							return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
						})}, "must-not-send-control-token")
						if err != nil {
							t.Fatal(err)
						}
						if operation == "refresh" {
							var result authorityv1.MachinePublicationSession
							result, err = client.RefreshMachinePublication(ctx, session, authorityv1.MachinePublicationRefresh{Assertion: "explicit-proof", Signature: "possession"})
							if result != (authorityv1.MachinePublicationSession{}) {
								t.Error("failed refresh returned session authority")
							}
						} else {
							err = client.CleanupMachinePublication(ctx, session, authorityv1.MachinePublicationCleanup{Assertion: "original-key-proof", InvocationId: "ivk_0123456789ABCDEFGHIJKL"})
						}
						if err == nil {
							t.Fatal("HTTP failure became quiet success")
						}
						if independent && !errors.Is(err, sentinel) {
							t.Error("authority HTTP error discarded the independent transport/read failure")
						}
						if cancellation == "live" {
							if ctx.Err() != nil || !errors.Is(err, ErrUnavailable) {
								t.Error("noncanceled HTTP failure changed unavailable classification")
							}
						} else {
							if ctx.Err() != context.Canceled || !errors.Is(err, context.Canceled) || !errors.Is(err, context.Cause(ctx)) || errors.Is(err, ErrUnavailable) {
								t.Error("canceled HTTP failure lost cancellation/custom cause or became unavailable")
							}
							if !independent && cancellation == "canceled" && !failure.Only(err, context.Canceled) {
								t.Error("cancellation-only HTTP failure ceased to be normal cancellation")
							}
						}
						if calls != 1 {
							t.Error("HTTP failure triggered another request")
						}
						if boundary == "read" && (body.reads != 1 || !body.closed) {
							t.Error("failed response body was not read once and closed")
						}
					})
				}
			}
		}
	}
}
