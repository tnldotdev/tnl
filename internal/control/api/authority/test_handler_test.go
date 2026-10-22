package authorityapi

import (
	"net/http"
	"testing"
)

func testHandler(t *testing.T, cfg Config, store Store) *http.ServeMux {
	t.Helper()
	handler, err := NewHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
