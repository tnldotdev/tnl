package controlapi

import (
	"context"
	"net/http"
	"testing"
)

func testHandler(t *testing.T, cfg Config, store Store, authorization BuiltinAuthorizationStore, readiness func(context.Context) error) *http.ServeMux {
	t.Helper()
	handler, err := NewHandler(cfg, store, authorization, readiness)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
