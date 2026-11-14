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

func TestPublicURLHTTPPolicyUsesSharedSettingsWithoutChangingExposure(t *testing.T) {
	period := Duration(time.Second)
	defaults := &Tunnel{Access: &Access{Mode: "anonymous", IP: []string{"192.0.2.1"}}, Limits: &Limits{
		HTTP:    &WorkLimits{Total: new(100), Rate: &Rate{Count: new(5), Per: &period}},
		Traffic: &TrafficLimits{Connections: new(8)},
	}}
	for _, deployment := range []string{"local", "production"} {
		value := &HTTPService{Access: &Access{Mode: "restricted"}, Limits: &WorkLimits{Concurrency: new(2), Rate: &Rate{Burst: new(3)}}}
		binding := &Tunnel{RequirePostQuantum: new(true)}
		configuration := TNL{Deployment: deployment, Tunnel: defaults, Services: Services{"web": {
			Tunnel: binding, Target: &ServiceTarget{Type: "address", Address: new(Target("http://app.internal:3000"))}, HTTP: value,
		}}}
		if err := ValidateTNL(configuration); err != nil {
			t.Fatalf("%s rejected shared HTTP policy: %v", deployment, err)
		}
		policy, err := ResolvePublicURLHTTP(defaults, binding, value)
		if err != nil || policy.Access.VisitorMode() != "restricted" || len(policy.Access.IP) != 0 ||
			*policy.Limits.Total != 100 || *policy.Limits.Concurrency != 2 || *policy.Limits.Rate.Count != 5 || *policy.Limits.Rate.Burst != 3 {
			t.Fatal("HTTP overrides lost inherited fields or retained the default IP restriction", policy, err)
		}
		if value.Limits.Total != nil || value.Limits.Rate.Count != nil || defaults.Limits.HTTP.Concurrency != nil ||
			binding.Access != nil || binding.Limits != nil || configuration.Services["web"].Public != nil {
			t.Fatal("HTTP resolution changed its input or selected service exposure")
		}
		inherited, err := ResolvePublicURLHTTP(defaults, binding, nil)
		if err != nil {
			t.Fatal(err)
		}
		inherited.Access.IP[0] = "198.51.100.1"
		if defaults.Access.IP[0] != "192.0.2.1" {
			t.Fatal("resolved access policy aliases its defaults")
		}
		value.Access = &Access{Mode: "anonymous"}
		if err := ValidateTNL(configuration); err != nil {
			t.Fatal("public URL lost its existing anonymous request capability", err)
		}
	}
}

func TestPublicURLHTTPPolicyRejectsDuplicateAndInvalidSettings(t *testing.T) {
	for _, test := range []struct {
		name    string
		binding *Tunnel
		http    *HTTPService
	}{
		{"duplicate access", &Tunnel{Access: &Access{Mode: "restricted"}}, &HTTPService{Access: &Access{Mode: "anonymous"}}},
		{"duplicate limits", &Tunnel{Limits: &Limits{HTTP: &WorkLimits{Total: new(100)}}}, &HTTPService{Limits: &WorkLimits{Concurrency: new(2)}}},
		{"invalid access", &Tunnel{}, &HTTPService{Access: &Access{Mode: "invalid"}}},
		{"invalid IP", &Tunnel{}, &HTTPService{Access: &Access{IP: []string{"not-an-address"}}}},
		{"empty IP", &Tunnel{}, &HTTPService{Access: &Access{IP: []string{}}}},
		{"invalid limit", &Tunnel{}, &HTTPService{Limits: &WorkLimits{Total: new(0)}}},
		{"incomplete rate", &Tunnel{}, &HTTPService{Limits: &WorkLimits{Rate: &Rate{Burst: new(2)}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ResolvePublicURLHTTP(nil, test.binding, test.http); err == nil {
				t.Fatal("ambiguous or invalid HTTP policy accepted")
			}
		})
	}
}
