package publisher

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
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
		if got.Path != want.path || got.Status != want.status || got.Origin != want.origin || got.Method != http.MethodGet ||
			got.ReceivedAt.IsZero() || got.Duration < 0 || got.Duration > time.Minute {
			t.Fatalf("observation %d = %+v", i, got)
		}
	}
}
