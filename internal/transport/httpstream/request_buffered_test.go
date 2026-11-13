package httpstream

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBufferedRequestRetainsTrailers(t *testing.T) {
	source := httptest.NewRequest("POST", "/", strings.NewReader("body"))
	source.Trailer = http.Header{"X-Digest": nil}
	Requests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simulate trailers becoming visible only at the incoming body's EOF.
		source.Trailer["X-Digest"] = []string{"one", "two"}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		forwarded := r.Clone(r.Context())
		forwarded.Body = io.NopCloser(strings.NewReader("body"))
		ForwardTrailers(r, forwarded)
		if strings.Join(forwarded.Trailer.Values("X-Digest"), ",") != "one,two" {
			t.Fatal("buffering lost trailers", forwarded.Trailer)
		}
	}), RequestBodyTimeout).ServeHTTP(httptest.NewRecorder(), source)
}
