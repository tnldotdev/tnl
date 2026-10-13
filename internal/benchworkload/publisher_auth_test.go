package benchworkload

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSavedSessionRequiredBeforePublisherNetworkAccess(t *testing.T) {
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := OpenPublishers(t.Context(), PublisherConfig{
		Server: "https://control.example.test", Team: "team_1", StateRoot: stateRoot,
		Transport: "mixed", Parallel: 1, ReadyTimeout: time.Second, StopTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "tnl auth login --server=https://control.example.test") {
		t.Fatalf("missing saved login should fail before network access: %v", err)
	}
}

func TestPublisherRequiresExplicitTeamBeforeOpeningState(t *testing.T) {
	_, err := OpenPublishers(t.Context(), PublisherConfig{Parallel: 1, Transport: TransportAuto, ReadyTimeout: time.Second, StopTimeout: time.Second, StateRoot: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "explicit team") {
		t.Fatalf("missing team = %v", err)
	}
}
