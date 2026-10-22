package benchworkload

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPVisitorMeasuresFreshAndReusedVerifiedConnections(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/reuse=%t", http2, reuse), func(t *testing.T) {
				server := httptest.NewUnstartedServer(Origin(32))
				server.EnableHTTP2 = http2
				server.StartTLS()
				defer server.Close()
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				visitor := (Visitor{Roots: roots, PayloadBytes: 32}).OpenHTTP(reuse, http2)
				defer visitor.Close()
				for index := range 2 {
					row := visitor.Request(t.Context(), server.URL, time.Now())
					protocol := map[bool]string{true: "HTTP/2.0", false: "HTTP/1.1"}[http2]
					if row.Error != "" || row.HTTPProtocol != protocol || row.Reused != (reuse && index > 0) || row.ResponseHeaders.IsZero() || row.FirstByte.Before(row.ResponseHeaders) {
						t.Fatalf("request %d: %+v", index, row)
					}
					if row.Reused && (row.TLS != 0 || row.Connect != 0) {
						t.Fatalf("reused socket included setup: %+v", row)
					}
				}
			})
		}
	}
}

func TestHTTPVisitorPreparationKeepsCredentialsOutOfResults(t *testing.T) {
	const secret = "preparation-secret"
	origin := Origin(32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prepare" {
			http.SetCookie(w, &http.Cookie{Name: "visitor", Value: secret, Secure: true, Path: "/"})
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if cookie, err := r.Cookie("visitor"); err != nil || cookie.Value != secret {
			http.Error(w, "missing permission", http.StatusForbidden)
			return
		}
		origin.ServeHTTP(w, r)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor := (Visitor{Roots: roots, Jar: jar, PayloadBytes: 32}).OpenHTTP(true, false)
	defer visitor.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/prepare", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := visitor.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if row := visitor.Request(t.Context(), server.URL, time.Now()); row.Error != "" {
		t.Fatalf("prepared request: %+v", row)
	}
}
