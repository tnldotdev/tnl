package clientauth

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorityclient"
)

type trackedBody struct {
	io.Reader
	read, closes int
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackedBody) Close() error { b.closes++; return nil }

func TestBearerTransportReplaysOnceAndTransfersFinalBody(t *testing.T) {
	for _, finalStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(http.StatusText(finalStatus), func(t *testing.T) {
			old := storedSession(issuedSession(t))
			rotated := issuedSession(t)
			rotated.RefreshExpiresAt = old.RefreshExpiresAt
			firstBody := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", 8<<10))}
			finalBody := &trackedBody{Reader: strings.NewReader("final response")}
			calls := 0
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/v1/auth/refresh" {
					return jsonResponse(200, rotated), nil
				}
				calls++
				if calls == 1 {
					return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`  bEaReR error="invalid_token" `}}, Body: firstBody}, nil
				}
				return &http.Response{StatusCode: finalStatus, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: finalBody}, nil
			})
			f.save(t, old)
			source := f.source(t)
			transport := &bearerTransport{base: f.transport, source: source}
			const payload = `{"target":"http://127.0.0.1:3000"}`
			originalBody := &trackedBody{Reader: strings.NewReader(payload)}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testControlOrigin+"/v1/routes?test=replay", originalBody)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "stable-key")
			originalHeaders := request.Header.Clone()
			var sentBodies []*trackedBody
			request.GetBody = func() (io.ReadCloser, error) {
				body := &trackedBody{Reader: strings.NewReader(payload)}
				sentBodies = append(sentBodies, body)
				return body, nil
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != finalStatus || response.Body != finalBody || finalBody.closes != 0 || finalBody.read != 0 {
				t.Fatal("final response ownership was not transferred to caller")
			}
			if firstBody.closes != 1 || firstBody.read != 4<<10 {
				t.Fatalf("discarded unauthorized response: closes=%d bytes=%d", firstBody.closes, firstBody.read)
			}
			if calls != 2 || len(sentBodies) != 2 || sentBodies[0] == sentBodies[1] {
				t.Fatalf("replay calls=%d bodies=%d", calls, len(sentBodies))
			}
			if originalBody.closes != 1 || originalBody.read != 0 {
				t.Fatalf("original body closes=%d bytes=%d", originalBody.closes, originalBody.read)
			}
			for _, body := range sentBodies {
				if body.closes != 1 || body.read != len(payload) {
					t.Fatalf("sent body closes=%d bytes=%d", body.closes, body.read)
				}
			}
			if !reflect.DeepEqual(request.Header, originalHeaders) {
				t.Fatal("caller headers were mutated")
			}
			requests := f.transport.snapshot()
			if len(requests) != 4 {
				t.Fatalf("requests=%d, want discovery, initial request, refresh, retry", len(requests))
			}
			for i, index := range []int{1, 3} {
				got := requests[index]
				token := old.AccessToken
				if i == 1 {
					token = rotated.AccessToken
				}
				if got.method != http.MethodPost || got.url != request.URL.String() || got.body != payload || got.header.Get("Authorization") != "Bearer "+token || got.header.Get("Idempotency-Key") != "stable-key" || got.header.Get("Content-Type") != "application/json" {
					t.Error("request replay changed method, URL, body, idempotency, content type, or bearer token")
				}
			}
			f.assertSession(t, storedSession(rotated))
		})
	}
}

func TestBearerTransportDoesNotRefreshOtherResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		challenge string
		explicit  bool
	}{
		{"no challenge", 401, "", false},
		{"other scheme", 401, "Basic realm=test", false},
		{"scheme prefix", 401, "Bearerish", false},
		{"forbidden", 403, "Bearer", false},
		{"unavailable", 503, "Bearer", false},
		{"explicit access token", 401, "Bearer", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader("caller response")}
			f := newAuthFixture(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: http.Header{"Www-Authenticate": {test.challenge}}, Body: body}, nil
			})
			old := storedSession(issuedSession(t))
			f.save(t, old)
			source := f.source(t)
			if test.explicit {
				source.explicit = old.AccessToken
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, testAuthorityOrigin+"/v1/identity", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&bearerTransport{base: f.transport, source: source}).RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.Body != body || body.closes != 0 || body.read != 0 || len(f.transport.snapshot()) != 2 {
				t.Fatal("nonqualifying response was consumed or retried")
			}
			f.assertSession(t, old)
		})
	}
}

func TestBearerTransportOriginRestrictionsAndExplicitAuthorization(t *testing.T) {
	for _, origin := range []string{testControlOrigin, testAuthorityOrigin, "https://unrelated.example", "https://control.example.attacker.example", "http://control.example", "https://control.example:444"} {
		for _, authorization := range []string{"", "Bearer route-session-credential"} {
			t.Run(origin+"/"+map[bool]string{false: "automatic", true: "explicit"}[authorization != ""], func(t *testing.T) {
				body := &trackedBody{Reader: strings.NewReader("response")}
				base := &recordingTransport{respond: func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: body}, nil
				}}
				source := &tokenSource{control: control{serverEndpoint: testControlOrigin, authorityEndpoint: testAuthorityOrigin}, explicit: "automatic-access"}
				// With explicit Authorization, no token lookup (and no state) is needed.
				if authorization != "" {
					source.explicit = ""
				}
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/resource", nil)
				if err != nil {
					t.Fatal(err)
				}
				if authorization != "" {
					request.Header.Set("Authorization", authorization)
				}
				response, err := (&bearerTransport{base: base, source: source}).RoundTrip(request)
				allowed := origin == testControlOrigin || origin == testAuthorityOrigin
				if !allowed {
					if err == nil || response != nil || len(base.snapshot()) != 0 {
						t.Fatal("credentials sent to an unexpected origin")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				requests := base.snapshot()
				wantAuth := authorization
				if wantAuth == "" {
					wantAuth = "Bearer automatic-access"
				}
				if len(requests) != 1 || requests[0].header.Get("Authorization") != wantAuth || request.Header.Get("Authorization") != authorization || response.Body != body || body.closes != 0 {
					t.Fatal("authorization was replaced, retried, or mutated")
				}
			})
		}
	}
}

func TestBearerTransportRefreshFailureClosesDiscardedResponse(t *testing.T) {
	old := storedSession(issuedSession(t))
	body := &trackedBody{Reader: strings.NewReader("expired")}
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/auth/refresh" {
			return problemResponse(401, "unauthenticated"), nil
		}
		return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: body}, nil
	})
	f.save(t, old)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, testControlOrigin+"/v1/routes", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&bearerTransport{base: f.transport, source: f.source(t)}).RoundTrip(request)
	if response != nil || !errors.Is(err, authorityclient.ErrUnauthenticated) || body.closes != 1 || len(f.transport.snapshot()) != 3 {
		t.Fatalf("refresh failure: closes=%d error=%v", body.closes, err)
	}
	f.assertSession(t, old)
}

func TestAuthenticatedRequestBodyFailuresDoNotSendPartialRequests(t *testing.T) {
	failure := errors.New("cannot reopen request body")
	for _, replayable := range []bool{false, true} {
		t.Run(map[bool]string{false: "no GetBody", true: "GetBody failure"}[replayable], func(t *testing.T) {
			base := &recordingTransport{respond: func(*http.Request) (*http.Response, error) { return nil, errors.New("unexpected request") }}
			source := &tokenSource{control: control{serverEndpoint: testControlOrigin}, explicit: "access"}
			original := &trackedBody{Reader: strings.NewReader("payload")}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testControlOrigin+"/v1/routes", original)
			if err != nil {
				t.Fatal(err)
			}
			if replayable {
				request.GetBody = func() (io.ReadCloser, error) { return nil, failure }
			}
			response, err := (&bearerTransport{base: base, source: source}).RoundTrip(request)
			if response != nil || err == nil || replayable && !errors.Is(err, failure) || len(base.snapshot()) != 0 || original.read != 0 || original.closes != 1 || request.Header.Get("Authorization") != "" {
				t.Fatalf("body preparation failure: %v", err)
			}
		})
	}
}

func TestBearerTransportReplayBodyFailureKeepsRefreshedSession(t *testing.T) {
	old := storedSession(issuedSession(t))
	rotated := issuedSession(t)
	rotated.RefreshExpiresAt = old.RefreshExpiresAt
	unauthorizedBody := &trackedBody{Reader: strings.NewReader("expired")}
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/auth/refresh" {
			return jsonResponse(200, rotated), nil
		}
		return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: unauthorizedBody}, nil
	})
	f.save(t, old)
	originalBody := &trackedBody{Reader: strings.NewReader("payload")}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testControlOrigin+"/v1/routes", originalBody)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	failure := errors.New("replay unavailable")
	firstBody := &trackedBody{Reader: strings.NewReader("payload")}
	request.GetBody = func() (io.ReadCloser, error) {
		calls++
		if calls == 1 {
			return firstBody, nil
		}
		return nil, failure
	}
	response, err := (&bearerTransport{base: f.transport, source: f.source(t)}).RoundTrip(request)
	if response != nil || !errors.Is(err, failure) || calls != 2 || originalBody.closes != 1 || originalBody.read != 0 || unauthorizedBody.closes != 1 || firstBody.closes != 1 || len(f.transport.snapshot()) != 3 {
		t.Fatalf("replay failure: calls=%d error=%v", calls, err)
	}
	f.assertSession(t, storedSession(rotated))
}

func TestBearerTransportNetworkFailureDoesNotRetryAgain(t *testing.T) {
	for _, failOnRetry := range []bool{false, true} {
		name := "initial request"
		if failOnRetry {
			name = "replayed request"
		}
		t.Run(name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			rotated := issuedSession(t)
			rotated.RefreshExpiresAt = old.RefreshExpiresAt
			failure := errors.New("network failed")
			firstBody := &trackedBody{Reader: strings.NewReader("expired")}
			calls := 0
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/v1/auth/refresh" {
					return jsonResponse(200, rotated), nil
				}
				calls++
				if failOnRetry && calls == 1 {
					return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: firstBody}, nil
				}
				return nil, failure
			})
			f.save(t, old)
			const payload = "request body"
			originalBody := &trackedBody{Reader: strings.NewReader(payload)}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testControlOrigin+"/v1/routes", originalBody)
			if err != nil {
				t.Fatal(err)
			}
			request.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(payload)), nil
			}
			response, err := (&bearerTransport{base: f.transport, source: f.source(t)}).RoundTrip(request)
			if response != nil || !errors.Is(err, failure) || originalBody.closes != 1 || originalBody.read != 0 {
				t.Fatalf("network failure=%v", err)
			}
			wantCalls, wantRequests := 1, 2
			want := old
			if failOnRetry {
				wantCalls, wantRequests, want = 2, 4, storedSession(rotated)
				if firstBody.closes != 1 {
					t.Fatal("discarded response leaked")
				}
			}
			if calls != wantCalls || len(f.transport.snapshot()) != wantRequests {
				t.Fatalf("unexpected network retry: calls=%d requests=%d", calls, len(f.transport.snapshot()))
			}
			f.assertSession(t, want)
		})
	}
}
