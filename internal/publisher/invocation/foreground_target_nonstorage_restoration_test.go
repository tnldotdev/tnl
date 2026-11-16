package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestForegroundRuntimeAddressesNeverReplaceSavedAppPlaceholder(t *testing.T) {
	f := newForegroundFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer second.Close()
	var mutations [][]byte
	previous := f.before
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/services" ||
			r.Method == http.MethodPut && r.URL.Path == "/v1/services/"+f.saved.Id {
			data, err := io.ReadAll(r.Body)
			err = errors.Join(err, r.Body.Close())
			if err != nil {
				t.Fatal("observe management declaration", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			mutations = append(mutations, bytes.Clone(data))
		}
		return previous(r)
	}
	steps := []struct {
		address string
		limits  applicationlimits.Limits
		policy  resolvedVisitorAccess
	}{
		{first.URL, applicationlimits.Limits{}, resolvedVisitorAccess{}},
		{second.URL, applicationlimits.Limits{}, resolvedVisitorAccess{}},
		{second.URL, applicationlimits.Limits{Concurrency: 7},
			resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous}},
	}
	for _, step := range steps {
		plan := foregroundPlan()
		plan.Target = step.address
		native, saved, actual, err := prepareForegroundService(ctx, f.services, PublicOptions{Target: step.address, Limits: step.limits}, step.policy, plan)
		if err != nil || native == nil || saved.Id != f.saved.Id || actual.Target != step.address {
			t.Fatal("foreground preparation lost its actual local listener or exact service", err)
		}
		configured, _, err := f.services.routes.GetServiceConfiguration(ctx, saved.Id)
		if err != nil || configured == nil || configured.Target != "app" {
			t.Fatal("foreground runtime address replaced the saved app placeholder", err)
		}
		managed, err := f.services.routes.GetService(ctx, saved.Id)
		if err != nil {
			t.Fatal(err)
		}
		access, err := native.Access(ctx)
		if err != nil || access == "" {
			t.Fatal("foreground signing authority was not usable", err)
		}
		stored, err := json.Marshal(struct {
			Service       controlv1.Service
			Configuration *controlv1.ProjectServiceConfiguration
		}{managed, configured})
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range append(append([][]byte(nil), mutations...), stored) {
			for _, address := range []string{first.URL, second.URL} {
				if bytes.Contains(data, []byte(address)) || bytes.Contains(data, []byte(strings.TrimPrefix(address, "http://"))) {
					t.Error("management declaration or saved response contains an actual local runtime address")
				}
			}
			for _, secret := range []string{access, `"session"`, `"access_token"`, `"refresh_token"`, `"run_token"`, `"enrollment_key"`, `"signing_key"`, `"private_key"`} {
				if bytes.Contains(data, []byte(secret)) {
					t.Error("saved declaration or management payload contains serving credentials")
				}
			}
		}
	}
	if f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || f.updates != 1 ||
		f.declaration.Target != "app" || len(mutations) != 4 {
		t.Fatal("listener replacement or explicit policy update changed the saved lifetime, key, or placeholder")
	}
}
