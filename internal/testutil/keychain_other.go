//go:build !darwin

package testutil

import "testing"

// UseClientKeychain leaves the ordinary file-backed client state on other
// platforms; subprocess tests use the same default protection in both processes.
func UseClientKeychain(t testing.TB) string {
	t.Helper()
	RequireTestTier(t, TestTierIntegration)
	return ""
}
