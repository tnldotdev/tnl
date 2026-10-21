package publisher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicURLStreamingUploadRetainsCookieFilteredTrailers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			var calls atomic.Int32
			ended := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(ended)
				calls.Add(1)
				if r.Header.Get("Cookie") != "app=kept" || r.Header.Get("Authorization") != "Bearer application" || r.Header.Get("X-Api-Key") != "application-key" {
					t.Error("cookie filtering changed application credentials")
				}
				if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
					t.Error(err)
					return
				}
				first := make([]byte, 5)
				if _, err := io.ReadFull(r.Body, first); err != nil || string(first) != "first" {
					t.Error("upload prefix", string(first), err)
					return
				}
				_, _ = io.WriteString(w, "early\n")
				_ = http.NewResponseController(w).Flush()
				last, err := io.ReadAll(r.Body)
				if err != nil || string(last) != "last" {
					t.Error("upload completion", string(last), err)
					return
				}
				if strings.Join(r.Trailer.Values("X-Upload-Digest"), ",") != "one,two" {
					t.Error("cookie-filtered upload lost trailers", r.Trailer)
				}
				_, _ = io.WriteString(w, "done\n")
			}))
			t.Cleanup(upstream.Close)
			route, _ := startLimitedTestPublicURL(t, upstream.URL, 1, 0)
			client := singleConnectionRouteClient(t, route, h2)
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() { cancel(); _ = writer.Close() })
			request, err := http.NewRequestWithContext(ctx, "POST", "https://route.example/upload", reader)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Cookie", feedbackBrowserCookieName+"=internal; app=kept")
			request.Header.Set("Authorization", "Bearer application")
			request.Header.Set("X-Api-Key", "application-key")
			request.Trailer = http.Header{"X-Upload-Digest": nil}
			responses := make(chan *http.Response, 1)
			failures := make(chan error, 1)
			go func() {
				response, err := client.Do(request)
				if err != nil {
					failures <- err
				}
				responses <- response
			}()
			if _, err := io.WriteString(writer, "first"); err != nil {
				t.Fatal(err)
			}
			response := awaitPublisherTest(t, responses)
			if response == nil {
				t.Fatal(awaitPublisherTest(t, failures))
			}
			defer response.Body.Close()
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if response.StatusCode != 200 || response.ProtoMajor != wantProtocol {
				t.Fatal("early response precondition", response.Status, response.Proto)
			}
			body := bufio.NewReader(response.Body)
			first, err := body.ReadString('\n')
			if err != nil || first != "early\n" {
				t.Fatal("early flush", first, err)
			}
			request.Trailer["X-Upload-Digest"] = []string{"one", "two"}
			if _, err := io.WriteString(writer, "last"); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			last, err := io.ReadAll(body)
			if err != nil || string(last) != "done\n" || calls.Load() != 1 {
				t.Fatal("stream completion or replay", string(last), calls.Load(), err)
			}
			awaitPublisherTest(t, ended)
		})
	}
}
