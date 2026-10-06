package localproxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMountedProxySelectsCompleteLongestPrefixAndPreservesPathsByDefault(t *testing.T) {
	upstream := func(label string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(response, label+":"+request.URL.RequestURI())
		}))
	}
	base, api, versioned := upstream("web"), upstream("api"), upstream("v1")
	defer base.Close()
	defer api.Close()
	defer versioned.Close()
	handler, err := NewWithMounts(base.URL, "web.example.test", 0, []Mount{
		{Prefix: "/api", Target: api.URL},
		{Prefix: "/api/v1", Target: versioned.URL, StripPrefix: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ requested, expected string }{
		{"/", "web:/"},
		{"/apian", "web:/apian"},
		{"/api", "api:/api"},
		{"/api/users?sort=asc", "api:/api/users?sort=asc"},
		{"/api/v1", "v1:/"},
		{"/api/v1/users?sort=asc", "v1:/users?sort=asc"},
		{"/api%2Fv1/users", "web:/api%2Fv1/users"},
		{"/api/v1/%2Fitem", "v1:/%2Fitem"},
	} {
		t.Run(test.requested, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.requested, nil)
			request.Host = "web.example.test"
			request.TLS = &tls.ConnectionState{ServerName: "web.example.test"}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Body.String() != test.expected {
				t.Fatalf("mount response = %d %q, want %q", response.Code, response.Body.String(), test.expected)
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "/api/private", nil)
	request.Host = "other.example.test"
	request.TLS = &tls.ConnectionState{ServerName: "web.example.test"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("different hostname reached mount: %d", response.Code)
	}
}

func TestMountedProxySharesPublicURLRequestLimitDuringStreams(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	mounted := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "first")
		response.(http.Flusher).Flush()
		close(started)
		<-release
		_, _ = io.WriteString(response, "last")
	}))
	defer mounted.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	base := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "web")
	}))
	defer base.Close()
	handler, err := NewWithMounts(base.URL, "web.example.test", 1, []Mount{{Prefix: "/api", Target: mounted.URL}})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "web.example.test"
		request.TLS = &tls.ConnectionState{ServerName: "web.example.test"}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- serve("/api/stream") }()
	<-started
	if response := serve("/"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("base service bypassed mounted stream limit: %d %s", response.Code, response.Body.String())
	}
	close(release)
	if response := <-finished; response.Code != http.StatusOK || response.Body.String() != "firstlast" || !response.Flushed {
		t.Fatalf("stream = %d %q flushed=%t", response.Code, response.Body.String(), response.Flushed)
	}
	if response := serve("/"); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "web" {
		t.Fatalf("request limit did not release: %d %q", response.Code, response.Body.String())
	}
}
