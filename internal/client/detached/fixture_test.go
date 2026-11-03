package detached

import (
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("detached process did not reach the expected state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
