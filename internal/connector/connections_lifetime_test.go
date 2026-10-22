package connector

import (
	"errors"
	"testing"
	"time"

	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	workloadclient "github.com/tnldotdev/tnl/internal/connector/workload"
)

func TestConnectionProcessLifetimeDoesNotResurrectWorkloadSessions(t *testing.T) {
	// an app may resume after its event loop/process was paused for longer than
	// an old snapshot. human authorization is rechecked rather than ending IPC.
	human := &nativeConnectionBackend{nativeConnectionSession: nativeConnectionSession{human: &Session{}, deadline: time.Now().Add(-2 * time.Hour)}}
	if deadline, err := human.healthy(); err != nil || !deadline.After(time.Now()) {
		t.Fatal("human owner retained the one-hour cliff", err)
	}
	workload := &nativeConnectionBackend{nativeConnectionSession: nativeConnectionSession{workload: &workloadclient.Client{}, deadline: time.Now().Add(-time.Second)}}
	if _, err := workload.healthy(); !errors.Is(err, connectionruntime.ErrExpired) {
		t.Fatal("process lifetime revived expired workload rights", err)
	}
}
