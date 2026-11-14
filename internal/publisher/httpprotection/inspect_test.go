package httpprotection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

type closingWAF struct {
	coraza.WAF
	close func() error
}

func (w closingWAF) Close() error { return w.close() }

func TestInspectorClosesOwnedWAF(t *testing.T) {
	p := inspector(t, policy.Settings{})
	owned := p.waf.(experimental.WAFCloser)
	calls := 0
	p.waf = closingWAF{WAF: p.waf, close: func() error {
		calls++
		return owned.Close()
	}}
	if err := p.Close(); err != nil || calls != 1 {
		t.Fatal("inspector did not release its engine", calls, err)
	}
	if _, err := os.Stat(p.dir); !os.IsNotExist(err) {
		t.Fatal("inspector retained its temporary directory", err)
	}
}

func TestInspectorClosePreservesIndependentFailures(t *testing.T) {
	engineErr := errors.New("engine cleanup failed")
	for _, leaked := range []bool{false, true} {
		t.Run(fmt.Sprint(leaked), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "inspection")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if leaked {
				if err := os.WriteFile(filepath.Join(dir, "buffer"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			p := &Inspector{dir: dir, waf: closingWAF{close: func() error { return engineErr }}}
			err := p.Close()
			var storageErr *os.PathError
			if !errors.Is(err, engineErr) || errors.As(err, &storageErr) != leaked {
				t.Fatal("inspector lost an independent cleanup failure", err)
			}
			if _, err := os.Stat(dir); !leaked && !os.IsNotExist(err) {
				t.Fatal("engine failure skipped directory cleanup", err)
			}
		})
	}
}

func inspector(t testing.TB, settings policy.Settings) *Inspector {
	t.Helper()
	p, err := New(settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestExclusions(t *testing.T) {
	attack := "' OR 1=1 --"
	p := inspector(t, policy.Settings{Exclusions: []policy.Exclusion{{RuleID: 942100, Path: "/search", Parameter: "q"}}})
	for _, test := range []struct {
		path string
		want int
	}{
		{"/search?q=" + url.QueryEscape(attack), 0},
		{"/search?other=" + url.QueryEscape(attack), 403},
		{"/search/other?q=" + url.QueryEscape(attack), 403},
		{"/elsewhere?q=" + url.QueryEscape(attack), 403},
		{"/search?q=" + url.QueryEscape("<script>alert(1)</script>"), 403},
	} {
		_, close, result := p.Inspect(request("GET", test.path, "", ""))
		close()
		if result.Status != test.want {
			t.Fatalf("%s: status=%d rules=%v", test.path, result.Status, result.RuleIDs)
		}
	}
}

func TestBuffersReleaseBeforeResponse(t *testing.T) {
	p := inspector(t, policy.Settings{})
	p.gate = make(chan struct{}, 1)
	for _, how := range []string{"read", "close", "cleanup", "cancel"} {
		t.Run(how, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r, cleanup, result := p.Inspect(request("POST", "/", "text/plain", strings.Repeat("x", 256<<10)).WithContext(ctx))
			defer cleanup()
			if result.Status != 0 || len(p.gate) != 1 {
				t.Fatalf("inspection %+v slots=%d", result, len(p.gate))
			}
			if _, close, result := p.Inspect(request("GET", "/", "", "")); result.Status != 503 {
				close()
				t.Fatal("gate did not reject without a queue")
			}
			switch how {
			case "read":
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Fatal(err)
				}
			case "close":
				_ = r.Body.Close()
			case "cleanup":
				cleanup()
			case "cancel":
				cancel()
				// synchronize with cleanup through the body lock, no sleeps.
				_ = r.Body.Close()
			}
			if len(p.gate) != 0 {
				t.Fatal("retained inspection slot")
			}
			files, err := os.ReadDir(p.dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("retained temporary resources: %v %v", files, err)
			}
		})
	}
}

func TestGateIsSharedAcrossPublications(t *testing.T) {
	first, second := inspector(t, policy.Settings{}), inspector(t, policy.Settings{})
	for _, p := range []*Inspector{first, second} {
		_, cleanup, result := p.Inspect(request("POST", "/", "text/plain", "retained"))
		t.Cleanup(cleanup)
		if result.Status != 0 {
			t.Fatal(result)
		}
	}
	_, cleanup, result := first.Inspect(request("GET", "/", "", ""))
	defer cleanup()
	if result.Status != 503 {
		t.Fatal("publications did not share inspection capacity", result)
	}
}

func TestStreamingAndUpgradeDoNotRetainSlots(t *testing.T) {
	p := inspector(t, policy.Settings{})
	p.gate = make(chan struct{}, 1)
	for _, upgrade := range []bool{false, true} {
		r := request("GET", "/", "", "")
		if upgrade {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Sec-WebSocket-Version", "13")
			r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		}
		p.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if len(p.gate) != 0 {
				t.Error("long response retains a slot")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if upgrade {
				w.WriteHeader(101)
			}
			w.(http.Flusher).Flush()
			_, close, result := p.Inspect(request("GET", "/next", "", ""))
			close()
			if result.Status != 0 {
				t.Error(result)
			}
		}), nil).ServeHTTP(httptest.NewRecorder(), r)
	}
}

func TestParserSafetyAndMultipart(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Block, policy.Detect} {
		p := inspector(t, policy.Settings{WAF: mode})
		for _, data := range []string{
			"[" + strings.Repeat("0,", 1000) + "0]",
			strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65),
		} {
			_, cleanup, result := p.Inspect(request("POST", "/", "application/json", data))
			cleanup()
			if result.Status != 400 && result.Status != 413 {
				t.Fatalf("truncated JSON in %s was accepted: %+v", mode, result)
			}
		}
		var data bytes.Buffer
		form := multipart.NewWriter(&data)
		_ = form.SetBoundary("tnl-boundary")
		_ = form.WriteField("name", "hello")
		file, err := form.CreateFormFile("file", "sample.bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.Write([]byte{0, 1, 255})
		_ = form.Close()
		r, cleanup, result := p.Inspect(request("POST", "/", form.FormDataContentType(), data.String()))
		if result.Status != 0 {
			cleanup()
			t.Fatalf("multipart in %s: %+v", mode, result)
		}
		forwarded, err := io.ReadAll(r.Body)
		cleanup()
		if err != nil || !bytes.Equal(forwarded, data.Bytes()) {
			t.Fatal("multipart bytes changed", err)
		}
	}
}

func TestConcurrentBodyCleanup(t *testing.T) {
	p := inspector(t, policy.Settings{})
	for range 10 {
		ctx, cancel := context.WithCancel(t.Context())
		r, cleanup, result := p.Inspect(request("POST", "/", "text/plain", strings.Repeat("x", 256<<10)).WithContext(ctx))
		if result.Status != 0 {
			t.Fatal(result)
		}
		var workers sync.WaitGroup
		workers.Go(func() { _, _ = io.Copy(io.Discard, r.Body) })
		workers.Go(cancel)
		workers.Go(cleanup)
		workers.Wait()
	}
}

func BenchmarkInspect(b *testing.B) {
	for _, size := range []int{1024, policy.DefaultBodyBytes, policy.MaxBodyBytes} {
		for _, kind := range []string{"application/octet-stream", "application/json", "multipart/form-data"} {
			b.Run(fmt.Sprintf("%s/%d", kind, size), func(b *testing.B) {
				p := inspector(b, policy.Settings{MaxBodyBytes: new(size)})
				data := strings.Repeat("x", size)
				switch kind {
				case "application/json":
					data = `{"value":"` + strings.Repeat("x", size-12) + `"}`
				case "multipart/form-data":
					var form bytes.Buffer
					w := multipart.NewWriter(&form)
					_ = w.SetBoundary("tnl-benchmark")
					for form.Len()+128 < size {
						_ = w.WriteField("a", "")
					}
					_ = w.Close()
					data, kind = form.String(), w.FormDataContentType()
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				b.ResetTimer()
				for range b.N {
					r, cleanup, result := p.Inspect(request("POST", "/", kind, data))
					if result.Status != 0 {
						cleanup()
						b.Fatalf("benchmark body rejected: size=%d status=%d rules=%v", len(data), result.Status, result.RuleIDs)
					}
					if result.Status == 0 {
						_, _ = io.Copy(io.Discard, r.Body)
					}
					cleanup()
				}
			})
		}
	}
}

func request(method, path, kind, data string) *http.Request {
	r := httptest.NewRequest(method, "https://app.example"+path, strings.NewReader(data))
	r.Header.Set("User-Agent", "tnl-test")
	r.Header.Set("Accept", "*/*")
	if kind != "" {
		r.Header.Set("Content-Type", kind)
	}
	return r
}

func TestManagedProfile(t *testing.T) {
	p := inspector(t, policy.Settings{})
	tests := []struct {
		method, path, kind, data string
		status                   int
	}{
		{"GET", "/", "", "", 0},
		{"POST", "/ping", "", "", 0},
		{"PATCH", "/api", "application/json", `{"name":"hello"}`, 0},
		{"PUT", "/api", "application/problem+json", `{"title":"hello"}`, 0},
		{"DELETE", "/api", "", "", 0},
		{"OPTIONS", "/api", "", "", 0},
		{"POST", "/upload", "application/octet-stream", "\x00\x01\xff", 0},
		{"POST", "/upload", "text/plain", "hello", 0},
		{"POST", "/upload", "", "hello", 403},
		{"GET", "/?q=" + url.QueryEscape("<script>alert(1)</script>"), "", "", 403},
		{"GET", "/?q=" + url.QueryEscape("' OR 1=1 --"), "", "", 403},
		{"POST", "/api", "application/json", `{"q":"<script>alert(1)</script>"}`, 403},
		{"POST", "/api", "application/x-www-form-urlencoded", "q=" + url.QueryEscape("<script>alert(1)</script>"), 403},
		{"POST", "/api", "application/json", `{invalid`, 400},
	}
	for _, test := range tests {
		t.Run(test.method+test.path+test.kind+test.data, func(t *testing.T) {
			r, close, result := p.Inspect(request(test.method, test.path, test.kind, test.data))
			defer close()
			if result.Status != test.status {
				t.Fatalf("status=%d want=%d rules=%v", result.Status, test.status, result.RuleIDs)
			}
			if test.status == 0 {
				data, err := io.ReadAll(r.Body)
				if err != nil || string(data) != test.data {
					t.Fatalf("forwarded body changed: %q %v", data, err)
				}
			}
		})
	}
}

func TestEmptyPOSTContentType(t *testing.T) {
	p := inspector(t, policy.Settings{})
	for _, present := range []bool{false, true} {
		r := request("POST", "/ping", "", "")
		if present {
			r.Header.Set("Content-Type", "")
		}
		_, cleanup, result := p.Inspect(r)
		cleanup()
		want := 0
		if present {
			want = http.StatusForbidden
		}
		if result.Status != want {
			t.Fatalf("empty header present=%t: status=%d want=%d rules=%v", present, result.Status, want, result.RuleIDs)
		}
	}
}

func TestModesAndCeiling(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Block, policy.Detect, policy.Off} {
		t.Run(string(mode), func(t *testing.T) {
			p := inspector(t, policy.Settings{WAF: mode, MaxBodyBytes: new(32)})
			for _, length := range []int{31, 32, 33} {
				for _, unknown := range []bool{false, true} {
					r := request("POST", "/", "text/plain", strings.Repeat("a", length))
					if unknown {
						r.ContentLength = -1
					}
					out, close, result := p.Inspect(r)
					want := 0
					if mode != policy.Off && length > 32 {
						want = 413
					}
					if result.Status != want {
						t.Fatalf("mode=%s size=%d unknown=%v: status=%d want=%d", mode, length, unknown, result.Status, want)
					}
					if want == 0 {
						b, err := io.ReadAll(out.Body)
						if err != nil || len(b) != length {
							t.Fatalf("body size=%d err=%v", len(b), err)
						}
					}
					close()
				}
			}
			_, close, result := p.Inspect(request("GET", "/?q="+url.QueryEscape("<script>alert(1)</script>"), "", ""))
			defer close()
			if (mode == policy.Block) != (result.Status == 403) {
				t.Fatalf("mode=%s result=%+v", mode, result)
			}
		})
	}
}
