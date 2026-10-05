package feedbacktoolbar

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInjectPreservesStreamingAndLimitsCSPToItsScript(t *testing.T) {
	upstream, writer := io.Pipe()
	defer upstream.Close()
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	go func() {
		_, _ = writer.Write([]byte(`<!doctype html><html><head data-test='>'>`))
		<-release
		_, _ = writer.Write([]byte(`<title>streamed</title></head><body>app</body></html>`))
		_ = writer.Close()
	}()
	response := &http.Response{
		StatusCode: http.StatusOK, ContentLength: 120, Body: upstream,
		Request: &http.Request{Method: http.MethodGet}, Header: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Content-Length":          {"120"},
			"ETag":                    {"old"},
			"Content-Security-Policy": {"default-src 'self'; script-src 'none'; style-src 'self'"},
		},
	}
	if err := Inject(response); err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ContentLength != -1 || response.Header.Get("Content-Length") != "" || response.Header.Get("ETag") != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("rewritten HTML headers = %#v", response.Header)
	}
	first := make(chan []byte, 1)
	go func() {
		var result []byte
		buffer := make([]byte, 4096)
		for len(result) < 4096 {
			count, err := response.Body.Read(buffer)
			result = append(result, buffer[:count]...)
			if bytes.Contains(result, []byte("<script")) || err != nil {
				break
			}
		}
		first <- result
	}()
	var prefix []byte
	select {
	case prefix = <-first:
	case <-time.After(time.Second):
		t.Fatal("feedback injection waited for the entire HTML response")
	}
	if !bytes.Contains(prefix, []byte("<head data-test='>'>")) || !bytes.Contains(prefix, []byte("<script")) ||
		!strings.Contains(response.Header.Get("Content-Security-Policy"), "'nonce-") ||
		!strings.Contains(response.Header.Get("Content-Security-Policy"), "style-src 'self' 'nonce-") {
		t.Fatalf("streamed HTML prefix=%q CSP=%q", prefix, response.Header.Get("Content-Security-Policy"))
	}
	close(release)
	rest, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Contains(rest, []byte("<body>app</body>")) {
		t.Fatalf("remaining HTML=%q, %v", rest, err)
	}
}

func TestInjectSkipsCompressedAttachmentsAndNonHTML(t *testing.T) {
	for _, test := range []struct {
		name, mediaType, encoding, disposition string
		status                                 int
	}{
		{"gzip", "text/html", "gzip", "", http.StatusOK},
		{"attachment", "text/html", "", "attachment", http.StatusOK},
		{"partial", "text/html", "", "", http.StatusPartialContent},
		{"json", "application/json", "", "", http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("app response")
			response := &http.Response{
				StatusCode: test.status, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
				Request: &http.Request{Method: http.MethodGet}, Header: make(http.Header),
			}
			response.Header.Set("Content-Type", test.mediaType)
			response.Header.Set("Content-Encoding", test.encoding)
			response.Header.Set("Content-Disposition", test.disposition)
			if err := Inject(response); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || !bytes.Equal(got, body) || response.ContentLength != int64(len(body)) {
				t.Fatalf("ineligible response changed: %q, %v", got, err)
			}
		})
	}
}
