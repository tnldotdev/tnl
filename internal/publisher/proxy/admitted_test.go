package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestAdmittedHTTPPreservesConnectorHostAndResponseHooks(t *testing.T) {
	var forwarded, observed, modified int
	handler, err := New(Config{Target: "3000", Hostname: "preview.example",
		Transport: func(*url.URL, TargetOptions, bool) (Transport, error) {
			return &ownedProxyTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
				forwarded++
				if r.Host != "127.0.0.1:8443" || r.Header.Get("X-Forwarded-Host") != r.Host {
					t.Error("admitted request lost its original connector host", r.Host, r.Header)
				}
				if r.Header.Get("X-Forwarded-For") == "attacker" || r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
					t.Error("admitted request forwarded visitor identity or a readiness secret")
				}
				return proxyTransportResponse(r), nil
			}}, nil
		},
		Hooks: httpstream.ResponseHooks{
			Observe: func(response *http.Response) error {
				observed++
				if response.Request.Host != "preview.example" {
					t.Error("response hook lost the owner-supplied visitor authority", response.Request.Host)
				}
				return nil
			},
			ModifyHTML: func(*http.Response) error { modified++; return nil },
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	request := ownedProxyRequest("/")
	request.Host = "127.0.0.1:8443"
	request = httpstream.WithVisitorHost(request, "preview.example")
	request.Header.Set("X-Forwarded-For", "attacker")
	request.Header.Set(httpstream.ReadinessProbeHeader, "private-proof")
	full := httptest.NewRecorder()
	handler.ServeHTTP(full, request)
	if full.Code != http.StatusBadRequest || forwarded != 0 {
		t.Fatal("public entry accepted a connector host", full.Code, forwarded)
	}
	admitted := httptest.NewRecorder()
	handler.ServeAdmittedHTTP(admitted, request)
	if admitted.Code != http.StatusOK || admitted.Body.String() != "captured target" || forwarded != 1 || observed != 1 || modified != 1 {
		t.Fatal("admitted entry bypassed forwarding or response hooks", admitted.Code, forwarded, observed, modified)
	}
}

func TestBothProxyEntriesRejectInvalidRequestShape(t *testing.T) {
	var forwarded int
	handler, err := New(Config{Target: "3000", Hostname: "preview.example",
		Transport: func(*url.URL, TargetOptions, bool) (Transport, error) {
			return &ownedProxyTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
				forwarded++
				return proxyTransportResponse(r), nil
			}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, test := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"connect", func(r *http.Request) { r.Method = http.MethodConnect }},
		{"absolute URL", func(r *http.Request) { r.URL.Scheme, r.URL.Host = "https", "preview.example" }},
		{"absolute request URI", func(r *http.Request) { r.RequestURI = "https://preview.example/" }},
		{"URL authority", func(r *http.Request) { r.URL.Host = "preview.example" }},
		{"header count", func(r *http.Request) { r.Header["Many-Values"] = make([]string, maxHeaderFields+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, serve := range []func(http.ResponseWriter, *http.Request){handler.ServeHTTP, handler.ServeAdmittedHTTP} {
				request := ownedProxyRequest("/")
				test.change(request)
				response := httptest.NewRecorder()
				serve(response, request)
				if response.Code != http.StatusBadRequest || forwarded != 0 {
					t.Fatal("invalid request reached the captured target", response.Code, forwarded)
				}
			}
		})
	}
	// count header values, not just distinct names, and retain the exact bound.
	request := ownedProxyRequest("/")
	request.Header["Many-Values"] = make([]string, maxHeaderFields)
	for i := range request.Header["Many-Values"] {
		request.Header["Many-Values"][i] = fmt.Sprint(i)
	}
	response := httptest.NewRecorder()
	handler.ServeAdmittedHTTP(response, request)
	if response.Code != http.StatusOK || forwarded != 1 {
		t.Fatal("admitted entry rejected the exact header bound", response.Code, forwarded)
	}
}

func ownedProxyRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Host = "preview.example"
	request.TLS = &tls.ConnectionState{ServerName: "preview.example"}
	return request
}

func proxyTransportResponse(request *http.Request) *http.Response {
	body := "captured target"
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
