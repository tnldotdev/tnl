package installed

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestInstalledJobKindProtocolMatrix(t *testing.T) {
	// these expected values are independent of protocol.Valid and the validator.
	// kubernetes connectors serve kubeconfig clients; kubeconfig is not a job kind.
	protocols := []struct {
		value                          string
		service, connector, deployment bool
	}{
		{"", false, false, true},
		{"http", true, true, false},
		{"tcp", true, true, false},
		{"mysql", true, true, false},
		{"postgres", true, true, false},
		{"kubernetes", true, true, false},
		{"redis", false, false, false},
		{"unknown", false, false, false},
		{"HTTP", false, false, false},
		{"KUBERNETES", false, false, false},
		{"http ", false, false, false},
		{"postgresql", false, false, false},
		{"kubeconfig", false, false, false},
	}
	for _, kind := range []Kind{KindService, KindConnector, KindDeployment} {
		t.Run(string(kind), func(t *testing.T) {
			for _, test := range protocols {
				name := test.value
				if name == "" {
					name = "empty"
				}
				t.Run(name, func(t *testing.T) {
					registry := userRegistry(t)
					job, identity, key := kindFixture(t, kind)
					job.Protocol = config.ProtocolName(test.value)
					if kind == KindService && test.value == "http" {
						job.Target = "http://127.0.0.1:3000"
					}
					if kind == KindService && test.value == "kubernetes" {
						job.Target = "https://127.0.0.1:6443"
						job.Trust = capturedTrust(t, "cluster.example", nil)
					}
					want := test.service
					switch kind {
					case KindConnector:
						want = test.connector
					case KindDeployment:
						want = test.deployment
					}
					err := installKind(t, registry, kind, job, identity, key)
					if !want {
						requireScopeFailure(t, err)
					} else if err != nil {
						t.Fatal("explicitly supported job protocol was rejected", err)
					}
					jobs, err := registry.List(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if !want && len(jobs) != 0 || want && (len(jobs) != 1 || jobs[0].Kind != kind || string(jobs[0].Protocol) != test.value) {
						t.Fatal("installed state disagreed with the independent literal matrix", jobs)
					}
				})
			}
		})
	}
}

func TestInstalledProtocolMatrixRestorationRejectsUnknownJobKinds(t *testing.T) {
	for _, kind := range []Kind{"kubeconfig", "unknown"} {
		t.Run(string(kind), func(t *testing.T) {
			registry := userRegistry(t)
			job, identity, key := kindFixture(t, KindService)
			job.Kind, job.Protocol = kind, "kubernetes"
			job.Target = "https://127.0.0.1:6443"
			job.Trust = capturedTrust(t, "cluster.example", nil)
			_, err := registry.Install(t.Context(), job, identity, key)
			requireScopeFailure(t, err)
			_, err = registry.InstallConnector(t.Context(), job)
			requireScopeFailure(t, err)
			if jobs, err := registry.List(t.Context()); err != nil || len(jobs) != 0 {
				t.Fatal("unknown job kind wrote installed state", jobs, err)
			}
		})
	}
}
