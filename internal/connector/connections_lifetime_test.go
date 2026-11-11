package connector

import (
	"errors"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func TestConnectionProcessLifetimeDoesNotResurrectWorkloadSessions(t *testing.T) {
	// an app may resume after its event loop/process was paused for longer than
	// an old snapshot. human authorization is rechecked rather than ending IPC.
	human := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{human: &Session{}, deadline: time.Now().Add(-2 * time.Hour)}}
	if deadline, err := human.healthy(); err != nil || !deadline.After(time.Now()) {
		t.Fatal("human owner retained the one-hour cliff", err)
	}
	workload := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: &workload.Client{}, deadline: time.Now().Add(-time.Second)}}
	if _, err := workload.healthy(); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("process lifetime revived expired workload rights", err)
	}
}

func TestConnectionOwnerDeclaresApplicationLifetimeAndSDKCapabilities(t *testing.T) {
	for _, test := range []struct {
		name       string
		workload   string
		parent     int
		sdk        *SDKOptions
		persistent bool
	}{
		{name: "human", persistent: true},
		{name: "job", workload: "worker"},
		{name: "application workload", workload: "worker", parent: 1, persistent: true},
		{name: "SDK", workload: "worker", parent: 1, sdk: &SDKOptions{}, persistent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := &connectorConnectionBackend{scope: connectorruntime.Context{Workload: test.workload}, parentPID: test.parent, sdk: test.sdk}
			config := b.ownerConfig()
			if config.Backend != b || config.Persistent != test.persistent || config.OwnerAlive == nil || config.AuthorizationDeadline == nil || config.Kubernetes != b {
				t.Fatal("composition lost its explicit lifetime or owned capabilities")
			}
			if (config.SDKPrepare != nil) != (test.sdk != nil) || (config.SDKWorkload != nil) != (test.sdk != nil) {
				t.Fatal("composition exposed SDK operations without an SDK registry")
			}
		})
	}
}
