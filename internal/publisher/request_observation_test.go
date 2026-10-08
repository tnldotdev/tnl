package publisher

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestObservationSeparatesLocalAndPublisherResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	var events []RequestObservation
	server, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "app.example", Target: upstream.URL,
		ObserveRequest: func(event RequestObservation) { events = append(events, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, test := range []struct {
		path   string
		status int
		origin string
	}{
		{"/ok?token=private", 204, "local_service"},
		{"/broken", 500, "local_service"},
		{"/invalid", 400, "tnl"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Host = "app.example"
		request.TLS = &tls.ConnectionState{ServerName: "app.example"}
		if test.path == "/invalid" {
			request.Host = "other.example"
		}
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s: status = %d", test.path, response.Code)
		}
	}
	if len(events) != 3 {
		t.Fatalf("observations = %+v", events)
	}
	for i, want := range []struct {
		path   string
		status int
		origin string
	}{
		{"/ok", 204, "local_service"}, {"/broken", 500, "local_service"}, {"/invalid", 400, "tnl"},
	} {
		got := events[i]
		if got.CaptureMode != "summary" || got.Detail != nil {
			t.Fatalf("default capture = %+v", got)
		}
		if got.Path != want.path || got.Status != want.status || got.Origin != want.origin || got.Method != http.MethodGet ||
			got.ReceivedAt.IsZero() || got.Duration < 0 || got.Duration > time.Minute {
			t.Fatalf("observation %d = %+v", i, got)
		}
	}
}

func TestDetailedRequestObservationRetainsBoundedRawData(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Set-Cookie", "secret=session")
		_, _ = io.WriteString(w, "response data")
	}))
	defer upstream.Close()
	var captured RequestObservation
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "app.example", Target: upstream.URL,
		RequestInspection: "detailed", ObserveRequest: func(event RequestObservation) { captured = event }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := httptest.NewRequest(http.MethodPost, "/hook?code=private", strings.NewReader(strings.Repeat("p", maxCapturedBodyBytes+10)))
	request.Host = "app.example"
	request.TLS = &tls.ConnectionState{ServerName: "app.example"}
	request.Header.Set("Authorization", "Bearer private")
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || captured.Detail == nil || captured.CaptureMode != "detailed" {
		t.Fatalf("response = %d, observation = %+v", response.Code, captured)
	}
	detail := captured.Detail
	requestBytes, err := base64.StdEncoding.DecodeString(detail.RequestBody.Base64)
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := base64.StdEncoding.DecodeString(detail.ResponseBody.Base64)
	if err != nil {
		t.Fatal(err)
	}
	if captured.Path != "/hook" || detail.Query != "code=private" || detail.RequestHeaders.Get("Authorization") != "Bearer private" ||
		detail.ResponseHeaders.Get("Set-Cookie") != "secret=session" || !detail.RequestBody.Truncated ||
		len(requestBytes) != maxCapturedBodyBytes || string(responseBytes) != "response data" {
		t.Fatalf("detail = %+v, request bytes = %d, response bytes = %q", detail, len(requestBytes), responseBytes)
	}
}
