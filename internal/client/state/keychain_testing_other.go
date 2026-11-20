//go:build !darwin

package state

// UseMemoryKeychainForTesting is unnecessary outside macOS; file protection is
// already isolated by each fixture's private state directory.
func UseMemoryKeychainForTesting() {}
