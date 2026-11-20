package publishingtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestForwardCanceledRequestAbortsResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("canceled forwarding reached the backend")
	}))
	defer backend.Close()
	f := &Fixture{backend: &testutil.PublishingFixture{URL: backend.URL}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "https://control.fixture/v1/services/service/runs/run/renew", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	var aborted any
	func() {
		defer func() { aborted = recover() }()
		f.forward(response, request, false)
	}()
	if aborted != http.ErrAbortHandler || response.Body.Len() != 0 || response.Code == http.StatusBadGateway {
		t.Fatal("canceled forwarding invented a control failure", aborted, response.Code, response.Body.String())
	}
}
