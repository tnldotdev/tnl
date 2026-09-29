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
		Server: "https://control.example.test", StateRoot: stateRoot,
		Transport: "mixed", Parallel: 1, ReadyTimeout: time.Second, StopTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "tnl login --server=https://control.example.test") {
		t.Fatalf("missing saved login should fail before network access: %v", err)
	}
}
