package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoRedirectsClonesSuppliedAndDefaultClients(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls++
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", destination.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	redirectChecks := 0
	original := &http.Client{
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			redirectChecks++
			return nil
		},
	}
	clone := NoRedirects(original)
	if clone == original || clone.Timeout != original.Timeout {
		t.Fatal("client was not cloned with its configuration")
	}
	for name, client := range map[string]*http.Client{
		"supplied": clone,
		"default":  NoRedirects(nil),
	} {
		t.Run(name, func(t *testing.T) {
			response, err := client.Get(source.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}
	if destinationCalls != 0 || redirectChecks != 0 {
		t.Fatalf("redirects reached destination=%d, original checks=%d", destinationCalls, redirectChecks)
	}

	response, err := original.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if destinationCalls != 1 || redirectChecks != 1 {
		t.Fatalf("original client changed: destination=%d, checks=%d", destinationCalls, redirectChecks)
	}
}
