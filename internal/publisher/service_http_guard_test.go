package publisher

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func TestServiceHTTPGuardRevocationAbortsActiveResponse(t *testing.T) {
	client, policy, update, token := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test:25443/", nil)
	r.Header.Set(visitorTokenHeader, token.Reveal())
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	prefix := make([]byte, 6)
	if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
		t.Fatal("response did not start", err)
	}
	update.View.VisitorPolicyRevision++
	update.View.ObservedAt = time.Now()
	update.View.ValidUntil = update.View.ObservedAt.Add(10 * time.Second)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err == nil {
		t.Fatal("revoked HTTP response ended successfully")
	}
	response, err = client.Do(r.Clone(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("revoked permission admitted another request")
	}
}
