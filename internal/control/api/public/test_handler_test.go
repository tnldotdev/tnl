package public

import (
	"context"
	"net/http"
	"testing"
)

func testHandler(t *testing.T, cfg Config, store AdminStore, authorization AuthorizationStore, readiness func(context.Context) error, features ...Stores) *http.ServeMux {
	t.Helper()
	stores := Stores{}
	if len(features) != 0 {
		stores = features[0]
	}
	stores.Admin = store
	handler, err := NewHandler(cfg, stores, authorization, readiness)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
