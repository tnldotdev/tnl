package workloadsetup

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestGoogleTrustedBindingDefaultsReuseAndRebinding(t *testing.T) {
	r := newResolver()
	calls := 0
	r.run = func(_ context.Context, directory, name string, args ...string) ([]byte, error) {
		calls++
		if directory != "/project" || name != "gcloud" || !reflect.DeepEqual(args, []string{"iam", "service-accounts", "describe", "orders@project.iam.gserviceaccount.com", "--format=json", "--quiet"}) {
			t.Fatal("incorrect trusted lookup", directory, name, args)
		}
		return []byte(`{"uniqueId":"112010400000000710080","email":"orders@project.iam.gserviceaccount.com"}`), nil
	}
	o := Options{Directory: "/project", Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Google: &config.WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Services: []string{"db"}}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil || calls != 1 {
		t.Fatal("initial name binding failed", err)
	}
	bound := first["app"]
	if bound.Google.ServiceAccount != "orders@project.iam.gserviceaccount.com" || bound.Trust.Claims["sub"] != "112010400000000710080" || bound.Trust.Audience != o.Server || bound.Trust.Issuer != config.GoogleWorkloadIssuer || bound.Trust.JwksUrl != config.GoogleWorkloadJWKS || bound.MaxDurationSeconds != 0 {
		t.Fatal("Google defaults changed", bound)
	}
	o.Previous = first
	r.run = func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("unchanged binding required provider authentication")
		return nil, ErrBinding
	}
	second, err := r.resolve(t.Context(), o)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("saved binding changed", err)
	}
	p := o.Workloads["app"]
	p.Google = &config.WorkloadGoogle{ServiceAccount: "212010400000000710080"}
	o.Workloads["app"] = p
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrRebinding) {
		t.Fatal("a different numeric identity silently rebound", err)
	}
	o.Previous = nil
	if fresh, err := r.resolve(t.Context(), o); err != nil || fresh["app"].Trust.Claims["sub"] != p.Google.ServiceAccount {
		t.Fatal("explicit numeric identity required metadata", err)
	}
}

func TestGoogleBindingRejectsInvalidMetadataAndPreservesAuthenticationCause(t *testing.T) {
	r := newResolver()
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Google: &config.WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Services: []string{"db"}}}}
	for _, output := range []string{
		`not-json`,
		`{"uniqueId":"112010400000000710080","email":"other@project.iam.gserviceaccount.com"}`,
		`{"uniqueId":"not-a-numeric-id","email":"orders@project.iam.gserviceaccount.com"}`,
		`{"uniqueId":"112010400000000710080","email":"orders@project.iam.gserviceaccount.com","disabled":true}`,
	} {
		r.run = func(context.Context, string, string, ...string) ([]byte, error) { return []byte(output), nil }
		if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) {
			t.Fatal("invalid account metadata established authority", err)
		}
	}
	cause := errors.New("Google account metadata is unavailable")
	r.run = func(context.Context, string, string, ...string) ([]byte, error) { return nil, cause }
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrGoogleAuthentication) || !errors.Is(err, cause) {
		t.Fatal("trusted setup lost its failure classification or cause", err)
	}
}
