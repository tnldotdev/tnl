package httpstream_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func hookStreamClient(t *testing.T, target *httptest.Server, hooks httpstream.ResponseHooks, wrap func(http.Handler) http.Handler) *http.Client {
	t.Helper()
	location, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		visitor, server := net.Pipe()
		workers.Go(func() {
			defer server.Close()
			if err := httpstream.Serve(ctx, server, location, func(ctx context.Context) (net.Conn, error) {
				if location.Scheme == "https" {
					dialer := tls.Dialer{Config: target.Client().Transport.(*http.Transport).TLSClientConfig}
					return dialer.DialContext(ctx, "tcp", location.Host)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", location.Host)
			}, wrap, hooks, httpstream.Drain{}); err != nil {
				t.Error(err)
			}
		})
		return visitor, nil
	}}
	t.Cleanup(func() { cancel(); transport.CloseIdleConnections(); workers.Wait() })
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestResponseObserverPreservesCompressionAndRejectsBeforeSendingHeaders(t *testing.T) {
	var observed atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("header observer disabled upstream compression")
		}
		response.Header().Set("Location", "https://provider.example/authorize?state=secret")
		response.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	client := hookStreamClient(t, upstream, httpstream.ResponseHooks{
		Observe: func(response *http.Response) error {
			observed.Store(true)
			if response.Header.Get("Location") == "" {
				t.Error("observer did not see upstream headers")
			}
			return diagnostic.Wrap(diagnostic.RequestRejected, errors.New("authorization redirect rejected"))
		},
	}, nil)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || !observed.Load() || response.StatusCode != http.StatusBadRequest || response.Header.Get("Location") != "" || strings.Contains(string(body), "secret") {
		t.Fatalf("rejected response leaked upstream redirect: %v, %s, %v", response.Status, body, err)
	}
}

type hookedBody struct {
	io.Reader
	io.Closer
}

func TestHTMLModificationKeepsStreamingTrailersAndVisitorAuthority(t *testing.T) {
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" || r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("HTML target received compression negotiation or readiness secret")
		}
		if r.Host == "visitor.example" {
			t.Error("response hook changed the selected upstream Host header")
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Trailer", "X-Finished")
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-release
		w.Header().Set("X-Finished", "yes")
		_, _ = io.WriteString(w, "last")
	}))
	defer upstream.Close()
	defer finish()
	var observed atomic.Bool
	client := hookStreamClient(t, upstream, httpstream.ResponseHooks{
		Observe: func(response *http.Response) error {
			if response.Request.Host != "visitor.example" || response.Request.URL.Host == response.Request.Host {
				t.Error("observer confused visitor authority with target identity")
			}
			observed.Store(true)
			return nil
		},
		ModifyHTML: func(response *http.Response) error {
			if !observed.Load() || response.Request.Host != "visitor.example" {
				t.Error("HTML modification ran before header observation or lost visitor authority")
			}
			response.Body = hookedBody{Reader: io.MultiReader(strings.NewReader("<script></script>"), response.Body), Closer: response.Body}
			response.ContentLength = -1
			response.Header.Del("Content-Length")
			return nil
		},
	}, nil)
	request, err := http.NewRequestWithContext(t.Context(), "GET", "http://visitor.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set(httpstream.ReadinessProbeHeader, "forged-proof")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	prefix := make([]byte, len("<script></script>first"))
	if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "<script></script>first" {
		t.Fatal("HTML modification buffered or changed the first bytes", string(prefix), err)
	}
	finish()
	suffix, err := io.ReadAll(response.Body)
	if err != nil || string(suffix) != "last" || response.Trailer.Get("X-Finished") != "yes" {
		t.Fatal("modified response lost body or trailers", string(suffix), response.Trailer, err)
	}
}

func TestResponseHooksObserveFailureWithoutRedialOrReplay(t *testing.T) {
	var calls, observed, failures atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, writer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(writer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		_ = writer.Flush()
	}))
	defer upstream.Close()
	client := hookStreamClient(t, upstream, httpstream.ResponseHooks{
		Observe: func(*http.Response) error { observed.Add(1); return nil },
		ObserveStatus: func(_ *http.Request, status int) {
			if status != 0 {
				t.Error("forwarding failure invented an upstream status", status)
			}
			failures.Add(1)
		},
	}, nil)
	for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
		response, err := client.Get("http://visitor.example/")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != status {
			t.Fatal("selected upstream response changed", response.Status, err)
		}
	}
	if calls.Load() != 1 || observed.Load() != 1 || failures.Load() != 1 {
		t.Fatal("upstream redialed/replayed or observation repeated", calls.Load(), observed.Load(), failures.Load())
	}
}
