package config

import (
	"reflect"
	"testing"
	"time"
)

func TestServiceHTTPRequestPolicyIsIndependentOfPlacementAndExposure(t *testing.T) {
	period := Duration(time.Second)
	for _, deployment := range []string{"local", "production"} {
		for _, public := range []bool{false, true} {
			configuration := TNL{Deployment: deployment, Services: Services{"web": {
				Public: new(public),
				Target: &ServiceTarget{Type: "address", Address: new(Target("http://app.internal:3000"))},
				HTTP: &HTTPService{Access: &Access{IP: []string{"192.0.2.1"}}, Limits: &WorkLimits{
					Total: new(100), Concurrency: new(2), Rate: &Rate{Count: new(5), Per: &period},
				}},
			}}}
			if err := ValidateTNL(configuration); err != nil {
				t.Fatalf("%s public=%t rejected HTTP policy: %v", deployment, public, err)
			}
			service := configuration.Services["web"]
			service.HTTP.Access.Mode = "anonymous"
			if err := ValidateTNL(configuration); err == nil {
				t.Fatalf("%s public=%t accepted anonymous service authority", deployment, public)
			}
		}
	}
}

func TestServiceHTTPDefaultsRequireExplicitHTTPSettings(t *testing.T) {
	defaults := &Tunnel{Access: &Access{IP: []string{"192.0.2.1"}}, Limits: &Limits{HTTP: &WorkLimits{Total: new(100)}}}
	value, err := ResolveServiceHTTP(defaults, nil)
	if err != nil || value != nil {
		t.Fatal("defaults implicitly enabled service HTTP settings", value, err)
	}
	value, err = ResolveServiceHTTP(defaults, &HTTPService{Limits: &WorkLimits{Concurrency: new(2)}})
	if err != nil || !reflect.DeepEqual(value.Access, defaults.Access) || value.Limits == nil || *value.Limits.Total != 100 || *value.Limits.Concurrency != 2 {
		t.Fatal("service HTTP defaults or per-field overrides lost", value, err)
	}
	if defaults.Limits.HTTP.Concurrency != nil {
		t.Fatal("resolving a service changed project defaults")
	}
	if _, err := ResolveServiceHTTP(defaults, &HTTPService{Limits: &WorkLimits{Total: new(0)}}); err == nil {
		t.Fatal("invalid request limit accepted")
	}
}

func TestLocalHTTPBehaviorDoesNotBecomeRemotePublisherWork(t *testing.T) {
	for _, value := range []*HTTPService{
		{Readiness: &Readiness{Path: "/health"}},
		{Open: new(true)},
		{Paths: map[string]PathMount{"/api": {Service: "api"}}},
	} {
		if err := ValidateServiceHTTP(value); err != nil {
			t.Fatal("request validation rejected local behavior", err)
		}
		if err := ValidateRemoteHTTP(value); err == nil {
			t.Fatal("remote publisher accepted local behavior")
		}
	}
}
