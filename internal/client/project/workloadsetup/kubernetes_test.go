package workloadsetup

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

const kubeContextJSON = `{"contexts":[{"name":"eks-development","context":{"namespace":"production","cluster":"eks"}}],"clusters":[{"name":"eks","cluster":{"server":"https://cluster.example.test"}}]}`

func TestKubernetesTrustedBindingDefaultsReuseAndRebinding(t *testing.T) {
	r := newResolver()
	calls := 0
	r.run = func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		calls++
		if name != "kubectl" {
			t.Fatal("wrong setup tool", name)
		}
		switch strings.Join(args, " ") {
		case "config view --minify --output=json":
			return []byte(kubeContextJSON), nil
		case "--context eks-development --namespace production get serviceaccount orders --output=json":
			return []byte(`{"metadata":{"namespace":"production","name":"orders","uid":"11111111-1111-4111-8111-111111111111"}}`), nil
		case "--context eks-development get --raw /.well-known/openid-configuration":
			return []byte(`{"issuer":"https://oidc.eks.us-west-2.amazonaws.com/id/example","jwks_uri":"https://oidc.eks.us-west-2.amazonaws.com/id/example/keys"}`), nil
		default:
			t.Fatal("unexpected trusted lookup", args)
			return nil, ErrBinding
		}
	}
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Kubernetes: &config.WorkloadKubernetes{ServiceAccount: "orders"}, Grants: config.ServiceVisitGrants("db")}}}
	first, err := r.resolve(t.Context(), o)
	if err != nil || calls != 3 {
		t.Fatal("initial Kubernetes binding failed", err, calls)
	}
	p := first["app"]
	if p.Kubernetes.Context != "eks-development" || p.Kubernetes.Namespace != "production" || p.Trust.Audience != o.Server || p.Trust.Claims["sub"] != "system:serviceaccount:production:orders" || p.Trust.Claims["service_account_uid"] != "11111111-1111-4111-8111-111111111111" || p.MaxDurationSeconds != 0 {
		t.Fatal("incorrect saved cluster identity", p)
	}
	o.Previous = first
	r.run = func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"config", "view", "--minify", "--output=json"}) {
			t.Fatal("unchanged setup contacted Kubernetes", args)
		}
		return []byte(kubeContextJSON), nil
	}
	if next, err := r.resolve(t.Context(), o); err != nil || !reflect.DeepEqual(first, next) {
		t.Fatal("saved Kubernetes binding changed", err)
	}
	policy := o.Workloads["app"]
	policy.Kubernetes = &config.WorkloadKubernetes{Context: "replacement", Namespace: "production", ServiceAccount: "orders"}
	o.Workloads["app"] = policy
	for _, test := range []struct {
		name, uid, issuer, keys string
		allowed                 bool
	}{
		{"recreated account", "22222222-2222-4222-8222-222222222222", p.Trust.Issuer, p.Trust.JwksUrl, false},
		{"another issuer", p.Trust.Claims["service_account_uid"], "https://another.example", p.Trust.JwksUrl, false},
		{"another key endpoint", p.Trust.Claims["service_account_uid"], p.Trust.Issuer, "https://another.example/keys", false},
		{"renamed context with same authority", p.Trust.Claims["service_account_uid"], p.Trust.Issuer, p.Trust.JwksUrl, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r.run = func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
				switch {
				case strings.Contains(strings.Join(args, " "), "config view"):
					return []byte(strings.ReplaceAll(kubeContextJSON, "eks-development", "replacement")), nil
				case strings.Contains(strings.Join(args, " "), "get serviceaccount"):
					return []byte(`{"metadata":{"namespace":"production","name":"orders","uid":"` + test.uid + `"}}`), nil
				default:
					return []byte(`{"issuer":"` + test.issuer + `","jwks_uri":"` + test.keys + `"}`), nil
				}
			}
			next, err := r.resolve(t.Context(), o)
			if test.allowed {
				if err != nil || !reflect.DeepEqual(next["app"].Trust, p.Trust) {
					t.Fatal("context alias changed the bound authority", err)
				}
			} else if !errors.Is(err, ErrRebinding) {
				t.Fatal("changed identity silently inherited authority", err)
			}
		})
	}
}

func TestKubernetesBindingRejectsInsecureContextAndKeepsAuthenticationCause(t *testing.T) {
	r := newResolver()
	o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Kubernetes: &config.WorkloadKubernetes{ServiceAccount: "orders"}, Grants: config.ServiceVisitGrants("db")}}}
	r.run = func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte(strings.Replace(kubeContextJSON, `"server":`, `"insecure-skip-tls-verify":true,"server":`, 1)), nil
	}
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) {
		t.Fatal("unverified setup server established authority", err)
	}
	cause := errors.New("cluster authentication unavailable")
	r.run = func(context.Context, string, string, ...string) ([]byte, error) { return nil, cause }
	if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrKubernetesAuthentication) || !errors.Is(err, cause) {
		t.Fatal("setup failure lost its classification or cause", err)
	}
}

func TestKubernetesSetupNamespaceDefaultsAndAudience(t *testing.T) {
	for _, test := range []struct{ name, contextNamespace, explicitNamespace, wantNamespace string }{
		{"context namespace", "production", "", "production"},
		{"default namespace", "", "", "default"},
		{"explicit namespace", "production", "applications", "applications"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newResolver()
			r.run = func(_ context.Context, directory, name string, args ...string) ([]byte, error) {
				if directory != "/project" || name != "kubectl" || len(args) < 2 || !reflect.DeepEqual(args[:2], []string{"--context", "eks-development"}) {
					t.Fatal("setup lost its selected context", directory, name, args)
				}
				switch strings.Join(args[2:], " ") {
				case "config view --minify --output=json":
					return []byte(strings.Replace(kubeContextJSON, `"namespace":"production"`, `"namespace":"`+test.contextNamespace+`"`, 1)), nil
				case "--namespace " + test.wantNamespace + " get serviceaccount orders --output=json":
					return []byte(`{"metadata":{"namespace":"` + test.wantNamespace + `","name":"orders","uid":"11111111-1111-4111-8111-111111111111"}}`), nil
				case "get --raw /.well-known/openid-configuration":
					return []byte(`{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/keys"}`), nil
				default:
					t.Fatal("unexpected trusted lookup", args)
					return nil, ErrBinding
				}
			}
			o := Options{Directory: "/project", Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Kubernetes: &config.WorkloadKubernetes{Context: "eks-development", Namespace: test.explicitNamespace, ServiceAccount: "orders", Audience: "tnl-orders"}, Grants: config.ServiceVisitGrants("db")}}}
			bound, err := r.resolve(t.Context(), o)
			if err != nil || bound["app"].Kubernetes.Namespace != test.wantNamespace || bound["app"].Trust.Audience != "tnl-orders" {
				t.Fatal("setup defaults or explicit audience changed", err)
			}
		})
	}
}

func TestKubernetesSetupRejectsMalformedMetadata(t *testing.T) {
	validAccount := `{"metadata":{"namespace":"production","name":"orders","uid":"11111111-1111-4111-8111-111111111111"}}`
	validDiscovery := `{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/keys"}`
	for _, test := range []struct{ name, configuration, account, discovery string }{
		{"missing context", `{}`, validAccount, validDiscovery},
		{"invalid config", `not-json`, validAccount, validDiscovery},
		{"http cluster", strings.Replace(kubeContextJSON, "https://cluster", "http://cluster", 1), validAccount, validDiscovery},
		{"wrong cluster", strings.Replace(kubeContextJSON, `"cluster":"eks"`, `"cluster":"another"`, 1), validAccount, validDiscovery},
		{"wrong account name", kubeContextJSON, strings.Replace(validAccount, "orders", "another", 1), validDiscovery},
		{"wrong namespace", kubeContextJSON, strings.Replace(validAccount, "production", "another", 1), validDiscovery},
		{"missing uid", kubeContextJSON, `{"metadata":{"name":"orders","namespace":"production"}}`, validDiscovery},
		{"invalid account", kubeContextJSON, `not-json`, validDiscovery},
		{"http issuer", kubeContextJSON, validAccount, strings.Replace(validDiscovery, "https://issuer", "http://issuer", 1)},
		{"http keys", kubeContextJSON, validAccount, strings.Replace(validDiscovery, "https://keys", "http://keys", 1)},
		{"missing keys", kubeContextJSON, validAccount, `{"issuer":"https://issuer.example"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newResolver()
			r.run = func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "config view"):
					return []byte(test.configuration), nil
				case strings.Contains(joined, "get serviceaccount"):
					return []byte(test.account), nil
				default:
					return []byte(test.discovery), nil
				}
			}
			o := Options{Server: "https://control.example", Workloads: map[string]config.Workload{"app": {Kubernetes: &config.WorkloadKubernetes{ServiceAccount: "orders"}, Grants: config.ServiceVisitGrants("db")}}}
			if _, err := r.resolve(t.Context(), o); !errors.Is(err, ErrBinding) {
				t.Fatal("invalid cluster metadata established authority", err)
			}
		})
	}
}
