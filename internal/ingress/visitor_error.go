package ingress

import (
	"context"
	"errors"
	"sync/atomic"
)

// VisitorError preserves diagnostic scope without treating a rejected candidate
// as a selected or admitted run. all original result causes remain unwrap-able.
type VisitorError struct {
	service, run, visitor string
	number                uint64
	candidate             string
	candidateNumber       uint64
	admitted              bool
	phase, denial         string
	operation, copyResult error
	cleanup, result       error
}

func (*VisitorError) Error() string      { return "ingress: visitor connection failed" }
func (e *VisitorError) GoString() string { return e.Error() }
func (e *VisitorError) Unwrap() error    { return e.result }

func (e *VisitorError) ForwardingScope() (service, run, visitor string, number uint64) {
	return e.service, e.run, e.visitor, e.number
}

func (e *VisitorError) ForwardingCandidate() (run string, number uint64) {
	return e.candidate, e.candidateNumber
}

func (e *VisitorError) ForwardingAdmitted() bool       { return e.admitted }
func (e *VisitorError) ForwardingPhase() string        { return e.phase }
func (e *VisitorError) ForwardingDenialReason() string { return e.denial }
func (e *VisitorError) ForwardingOperation() error     { return e.operation }
func (e *VisitorError) ForwardingCopyResult() error    { return e.copyResult }
func (e *VisitorError) ForwardingCleanup() error       { return e.cleanup }

// one accepted connection owns this diagnostic carrier through physical release.
// only the capacity callback writes admitted from another worker. none of these
// values is read by authorization, selection, metering, or transport policy.
type visitorDiagnostic struct {
	VisitorError
	admitted atomic.Bool
}

type visitorDiagnosticKey struct{}

func visitorDiagnosticFrom(ctx context.Context) *visitorDiagnostic {
	value, _ := ctx.Value(visitorDiagnosticKey{}).(*visitorDiagnostic)
	return value
}

func (d *visitorDiagnostic) finish(operation, release error) error {
	if operation == nil && release == nil {
		return nil
	}
	result := d.VisitorError
	result.operation, result.result = operation, errors.Join(operation, release)
	result.cleanup = errors.Join(result.cleanup, release)
	result.admitted = d.admitted.Load()
	return &result
}
