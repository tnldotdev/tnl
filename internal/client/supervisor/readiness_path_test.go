package supervisor

import (
	"errors"
	"testing"
)

func TestInstalledReadinessPathValidation(t *testing.T) {
	for _, path := range []string{"", "/", "/health", "/health/live", "health", "//elsewhere", "/health?token=secret", "/__tnl/login", "/a/../health", "/health\n"} {
		t.Run(path, func(t *testing.T) {
			job, _, _ := fixture(t, "web")
			job.ReadinessPath = path
			err := validateJob(&job)
			valid := path == "" || path == "/" || path == "/health" || path == "/health/live"
			if valid && err != nil || !valid && !errors.Is(err, ErrScope) {
				t.Fatal("invalid readiness path classification", err)
			}
		})
	}
}
