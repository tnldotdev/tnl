package service

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
)

func serviceHTTPAwait[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("service HTTP stream did not make progress")
		var zero T
		return zero
	}
}

func TestServiceHTTPProtocolsKeepStreamingBodiesAndTrailers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name, protocol := "http1", 1
		if h2 {
			name, protocol = "http2", 2
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan http.Header, 1)
			client, _, _, token := serviceHTTPProtocolFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
					t.Error(err)
					return
				}
				prefix := make([]byte, 5)
				if _, err := io.ReadFull(r.Body, prefix); err != nil || string(prefix) != "first" {
					t.Error("upload prefix changed", string(prefix), err)
					return
				}
				w.Header().Set("Trailer", "X-Response-Digest")
				_, _ = io.WriteString(w, "early\n")
				_ = http.NewResponseController(w).Flush()
				rest, err := io.ReadAll(r.Body)
				if err != nil || string(rest) != "last" {
					t.Error("upload remainder changed", string(rest), err)
					return
				}
				received <- r.Trailer.Clone()
				_, _ = io.WriteString(w, "done\n")
				w.Header().Set("X-Response-Digest", "complete")
			}), h2)
			reader, writer := io.Pipe()
			defer writer.Close()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://preview.example.test/upload", reader)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			request.Trailer = http.Header{"X-Upload-Digest": nil}
			type result struct {
				response *http.Response
				err      error
			}
			replies := make(chan result, 1)
			go func() { response, err := client.Do(request); replies <- result{response, err} }()
			if _, err := io.WriteString(writer, "first"); err != nil {
				t.Fatal(err)
			}
			reply := serviceHTTPAwait(t, replies)
			if reply.err != nil {
				t.Fatal(reply.err)
			}
			defer reply.response.Body.Close()
			if reply.response.StatusCode != http.StatusOK || reply.response.ProtoMajor != protocol {
				t.Fatal("HTTP protocol or admission changed", reply.response.Status, reply.response.Proto)
			}
			body := bufio.NewReader(reply.response.Body)
			if line, err := body.ReadString('\n'); err != nil || line != "early\n" {
				t.Fatal("response did not flush before upload EOF", line, err)
			}
			request.Trailer["X-Upload-Digest"] = []string{"one", "two"}
			if _, err := io.WriteString(writer, "last"); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			if got := serviceHTTPAwait(t, received); strings.Join(got.Values("X-Upload-Digest"), ",") != "one,two" {
				t.Fatal("request trailers changed", got)
			}
			if rest, err := io.ReadAll(body); err != nil || string(rest) != "done\n" || reply.response.Trailer.Get("X-Response-Digest") != "complete" {
				t.Fatal("response body or trailers changed", string(rest), err)
			}
		})
	}
}

func TestServiceHTTPProtocolsRequireExactAuthority(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			calls := make(chan struct{}, 8)
			client, _, _, token := serviceHTTPProtocolFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- struct{}{}
				w.WriteHeader(http.StatusNoContent)
			}), h2)
			for _, authority := range []string{"preview.example.test", "preview.example.test:443", "other.example.test", "preview.example.test:8443"} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = authority
				request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				want := http.StatusMisdirectedRequest
				if authority == "preview.example.test" || authority == "preview.example.test:443" {
					want = http.StatusNoContent
				}
				if response.StatusCode != want {
					t.Fatalf("authority %s: status %d, want %d", authority, response.StatusCode, want)
				}
			}
			if len(calls) != 2 {
				t.Fatal("invalid HTTP authority reached the target", len(calls))
			}
		})
	}
}
