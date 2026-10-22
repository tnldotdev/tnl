package webhookcatalog

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCatalogUsesWebhookOnlyFeedAndBoundedLastGood(t *testing.T) {
	now := time.Now()
	var requests int
	var unavailable bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("User-Agent") != "tnld" {
			t.Errorf("provider request user agent = %q", request.Header.Get("User-Agent"))
		}
		if unavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = response.Write([]byte(`{"hooks":["192.0.2.1","2001:db8::/48"],"actions":["0.0.0.0/0"]}`))
	}))
	defer server.Close()
	catalog := newCatalog(server.Client(), map[string]definition{"github": {url: server.URL, field: "hooks"}})
	catalog.now = func() time.Time { return now }
	first, err := catalog.Read(t.Context(), "github")
	if err != nil || first.MaxAge != 900 || first.ETag == "" ||
		first.Source.Kind != "ip_ranges" || !slices.Equal(first.Source.Ranges, []string{"192.0.2.1/32", "2001:db8::/48"}) {
		t.Fatalf("selected GitHub hooks = %+v, %v", first, err)
	}
	now = now.Add(14 * time.Minute)
	if _, err := catalog.Read(t.Context(), "github"); err != nil || requests != 1 {
		t.Fatalf("fresh source refetched: %d, %v", requests, err)
	}
	unavailable = true
	now = now.Add(2 * time.Minute)
	stale, err := catalog.Read(t.Context(), "github")
	if err != nil || stale.MaxAge != 0 || stale.ETag != first.ETag || requests != 2 {
		t.Fatalf("bounded last-good source = %+v, requests=%d, error=%v", stale, requests, err)
	}
	now = now.Add(25 * time.Hour)
	if _, err := catalog.Read(t.Context(), "github"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired source = %v", err)
	}
}

func TestCatalogRejectsInvalidRangesAndRecognizesUnrestrictedProviders(t *testing.T) {
	for _, addresses := range [][]string{
		nil, {"0.0.0.0/0"}, {"::/0"}, {"192.0.2.7/24"}, {"bad"}, {"192.0.2.1", "192.0.2.1/32"},
	} {
		if _, err := ipSource(addresses); err == nil {
			t.Errorf("accepted invalid source: %v", addresses)
		}
	}
	for _, test := range []struct{ provider, body, field string }{
		{"stripe", `{"WEBHOOKS":[]}`, "WEBHOOKS"},
		{"linear", `{"codingSessionIps":["192.0.2.1"]}`, "ips"},
		{"clerk", `{"us":["192.0.2.1"],"metadata":"unexpected"}`, ""},
		{"auth0", `{"regions":{"US":{"ipv4_cidrs":[]}}}`, ""},
	} {
		values, err := feedAddresses(test.provider, []byte(test.body), test.field)
		if err == nil {
			_, err = ipSource(values)
		}
		if err == nil {
			t.Errorf("accepted invalid %s feed", test.provider)
		}
	}
	catalog := New(nil)
	source, err := catalog.Read(t.Context(), "custom")
	if err != nil || source.Source.Kind != "*" || len(source.Source.Ranges) != 0 {
		t.Fatalf("custom source = %+v, %v", source, err)
	}
	if _, err := catalog.Read(t.Context(), "svix"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown provider = %v", err)
	}
	if len(source.ETag) < 4 || !strings.HasPrefix(source.ETag, `"`) {
		t.Fatalf("missing source ETag: %q", source.ETag)
	}
}
