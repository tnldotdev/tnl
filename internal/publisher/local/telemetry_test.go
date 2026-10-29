package local

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestAppWorkflowPreparationsCaptureIndependentTelemetryBeforeWaiting(t *testing.T) {
	for _, kind := range []string{"app", "named"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := testAppRuntime(t)
			address := config.Target("127.0.0.1:4100")
			for _, name := range []string{"web", "api"} {
				definition := config.Service{}
				if kind == "named" {
					definition.Target = &config.ServiceTarget{Type: "address", Address: &address}
				}
				a.project.Config.Services[name] = definition
			}
			_, digest, err := a.project.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			captured := map[string]bool{}
			firstID := ""
			for index, name := range []string{"web", "api", "web"} {
				want := index == 0
				input := want
				decision := &input
				if index == 2 {
					decision = nil
					if err := a.manager.Unregister(firstID, strings.Repeat("a", 32)); err != nil {
						t.Fatal(err)
					}
				}
				owner := strings.Repeat(string(rune('a'+index)), 32)
				release, err := a.beginPreparation(t.Context(), name)
				if err != nil {
					t.Fatal(err)
				}
				var once sync.Once
				unblock := func() { once.Do(release) }
				t.Cleanup(unblock)
				type result struct {
					id  string
					err error
				}
				done := make(chan result, 1)
				go func() {
					if kind == "app" {
						assignment, err := a.prepare(t.Context(), publisherprotocol.Prepare{Version: 1, Service: name, Directory: a.project.Root, Owner: owner, PID: os.Getpid(), Framework: publisherprotocol.FrameworkNode, TelemetryDisabled: decision})
						done <- result{assignment.RegistrationID, err}
					} else {
						registration, err := a.acquire(t.Context(), publisherprotocol.Lease{Service: name, Owner: owner, Pid: os.Getpid(), ConfigurationDigest: digest, TelemetryDisabled: decision})
						done <- result{registration.RegistrationID, err}
					}
				}()
				deadline := time.Now().Add(3 * time.Second)
				for {
					a.mu.Lock()
					waiting := a.preparing[name].users == 2
					a.mu.Unlock()
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("preparation did not reach its wait boundary")
					}
					time.Sleep(time.Millisecond)
				}
				input = !want
				unblock()
				select {
				case accepted := <-done:
					if accepted.err != nil {
						t.Fatal(accepted.err)
					}
					captured[accepted.id] = want
					if index == 0 {
						firstID = accepted.id
					}
				case <-time.After(3 * time.Second):
					t.Fatal("preparation did not finish")
				}
				a.mu.Lock()
				for id, want := range captured {
					if got := a.prepared[id].telemetryDisabled; got != want {
						a.mu.Unlock()
						t.Fatalf("%s preparation %s changed a sibling's captured decision: %t want %t", kind, id, got, want)
					}
				}
				a.mu.Unlock()
			}
		})
	}
}
