package public

import (
	"context"
	"net/http"
	"testing"
)

// Store composes the base fixtures; optional API stores are always explicit.
type Store interface {
	PublicURLStore
	CertificateStore
	AdminStore
}

func testHandler(t *testing.T, cfg Config, store Store, authorization AuthorizationStore, readiness func(context.Context) error, features ...Stores) *http.ServeMux {
	t.Helper()
	stores := Stores{}
	if len(features) != 0 {
		stores = features[0]
	}
	stores.PublicURLs, stores.Certificates, stores.Admin = store, store, store
	handler, err := NewHandler(cfg, stores, authorization, readiness)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
