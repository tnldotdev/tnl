package failure

// KeychainFailure identifies a client-state Keychain condition, not an OSStatus.
type KeychainFailure uint8

const (
	KeychainAccess KeychainFailure = iota
	KeychainTimeout
	KeychainCanceled
	KeychainUnavailable
	KeychainMissing
)

// ClientKeychainError carries only authored context and a non-sensitive cause.
// command output and stored values must never be retained in Cause.
type ClientKeychainError struct {
	Kind  KeychainFailure
	Cause error
}

func (e *ClientKeychainError) Error() string { return "could not use the client-state Keychain" }
func (e *ClientKeychainError) Unwrap() error { return e.Cause }
