package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedHTTPSMetadata(t *testing.T) {
	for _, header := range []string{"X-Forwarded-For", "Fly-Client-IP"} {
		t.Run(header, func(t *testing.T) {
			calls := 0
			handler, err := (Config{Origin: "https://control.example", TrustedPeers: []string{"192.0.2.8/32"}, ClientIPHeader: header}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.RemoteAddr != "198.51.100.4:0" || r.URL.Scheme != "https" || r.URL.Host != "control.example" || r.TLS != nil {
					t.Errorf("unexpected backend request: %s %s TLS=%v", r.RemoteAddr, r.URL, r.TLS)
				}
				for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-For", "X-Forwarded-Proto", "Fly-Client-IP"} {
					if r.Header.Get(name) != "" {
						t.Errorf("forwarded input survived: %s", name)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name   string
				modify func(*http.Request)
				status int
			}{
				{"trusted", func(*http.Request) {}, 204},
				{"untrusted spoof", func(r *http.Request) { r.RemoteAddr = "192.0.2.9:1234" }, 403},
				{"missing source", func(r *http.Request) { r.Header.Del(header) }, 400},
				{"source chain", func(r *http.Request) { r.Header.Set(header, "198.51.100.4, 192.0.2.8") }, 400},
				{"duplicate source", func(r *http.Request) { r.Header.Add(header, "198.51.100.4") }, 400},
				{"plaintext", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }, 400},
				{"missing protocol", func(r *http.Request) { r.Header.Del("X-Forwarded-Proto") }, 400},
				{"duplicate protocol", func(r *http.Request) { r.Header.Add("X-Forwarded-Proto", "https") }, 400},
				{"host injection", func(r *http.Request) { r.Host = "evil.example" }, 400},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := httptest.NewRequest("GET", "http://control.example/", nil)
					r.RemoteAddr = "192.0.2.8:1234"
					r.Header.Set(header, "198.51.100.4")
					r.Header.Set("X-Forwarded-Proto", "https")
					r.Header.Set("X-Forwarded-Host", "evil.example")
					r.Header.Set("X-Forwarded-Port", "80")
					r.Header.Set("Forwarded", "for=evil;proto=http")
					test.modify(r)
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					if w.Code != test.status {
						t.Fatalf("status = %d, want %d", w.Code, test.status)
					}
				})
			}
			if calls != 1 {
				t.Fatalf("admitted %d requests", calls)
			}
		})
	}
}

func TestLocalHTTPDoesNotRequireOrTrustProxyHeaders(t *testing.T) {
	called := 0
	handler, err := (Config{Origin: "http://localhost:8445"}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.URL.Scheme != "http" || r.URL.Host != "localhost:8445" || r.RemoteAddr != "127.0.0.1:1234" || r.Header.Get("X-Forwarded-For") != "" {
			t.Fatalf("local request trusted forwarded input: %+v", r)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost:8445", "attacker.example", "localhost:8446"} {
		r := httptest.NewRequest(http.MethodGet, "http://localhost:8445/v1/ready", nil)
		r.Host, r.RemoteAddr = host, "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", "203.0.113.1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		expected := http.StatusBadRequest
		if host == "localhost:8445" {
			expected = http.StatusNoContent
		}
		if w.Code != expected {
			t.Fatalf("host %s: %d", host, w.Code)
		}
	}
	if called != 1 {
		t.Fatal("host mismatch reached local control")
	}
	if err := (Config{Origin: "http://control.example"}).Validate(); err == nil {
		t.Fatal("remote plaintext origin accepted")
	}
}
