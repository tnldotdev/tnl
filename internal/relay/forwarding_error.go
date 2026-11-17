package relay

import "errors"

// ForwardingError retains one validated forwarding header's scope and the
// separate copy and final-close results. it grants no visitor permission.
type ForwardingError struct {
	service, run, visitor string
	number                uint64
	phase                 string
	operation, copyResult error
	cleanup, result       error
}

func (*ForwardingError) Error() string      { return "relay: visitor forwarding failed" }
func (e *ForwardingError) GoString() string { return e.Error() }
func (e *ForwardingError) Unwrap() error    { return e.result }

func (e *ForwardingError) ForwardingScope() (service, run, visitor string, number uint64) {
	return e.service, e.run, e.visitor, e.number
}

func (e *ForwardingError) ForwardingPhase() string     { return e.phase }
func (e *ForwardingError) ForwardingOperation() error  { return e.operation }
func (e *ForwardingError) ForwardingCopyResult() error { return e.copyResult }
func (e *ForwardingError) ForwardingCleanup() error    { return e.cleanup }

func (e *ForwardingError) finish(operation error) error {
	if operation == nil && e.cleanup == nil {
		return nil
	}
	e.operation = operation
	e.result = errors.Join(operation, e.cleanup)
	return e
}
