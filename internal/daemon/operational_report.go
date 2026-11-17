package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/relay"
)

// operationalReport is an observation-only value. it contains no error handles,
// socket addresses, source proofs, credentials, or free-form cause text. changing
// this snapshot cannot replace or mutate the error sent to production reporting.
type operationalReport struct {
	operation                                    failure.Operation
	reason                                       failure.Reason
	service, run, visitor                        string
	number                                       uint64
	candidate                                    string
	candidateNumber                              uint64
	admitted                                     bool
	phase, denial                                string
	admissionCause, admissionOnly                bool
	result, operationResult, copyResult, cleanup causeSnapshot
}

type causeSnapshot struct {
	nodes     []causeNode
	truncated bool
}

type causeNode struct {
	kind                               string
	parent                             int
	eof, canceled, deadline, admission bool
	native                             string
	streamID                           int64
	code                               uint64
	remote                             bool
}

func (d *daemon) reportOperationalError(ctx context.Context, operation failure.Operation, reason failure.Reason, cause error) {
	// the original report is unconditional and receives the original error.
	// the observer runs afterward and receives only a detached safe projection.
	logOperationalError(ctx, operation, reason, cause)
	if cause != nil && d.observeOperationalReport != nil {
		d.observeOperationalReport(snapshotOperationalReport(operation, reason, cause))
	}
}

func snapshotOperationalReport(operation failure.Operation, reason failure.Reason, cause error) operationalReport {
	if specific, ok := failure.ReasonOf(cause); ok {
		reason = specific
	}
	result := operationalReport{
		operation: operation, reason: reason, phase: "process", result: snapshotCauses(cause),
		admissionCause: errors.Is(cause, ingress.ErrServiceAdmission), admissionOnly: failure.Only(cause, ingress.ErrServiceAdmission),
	}
	var forwarded *relay.ForwardingError
	var visitor *ingress.VisitorError
	switch {
	case errors.As(cause, &forwarded):
		result.service, result.run, result.visitor, result.number = forwarded.ForwardingScope()
		result.phase = forwarded.ForwardingPhase()
		result.operationResult = snapshotCauses(forwarded.ForwardingOperation())
		result.copyResult = snapshotCauses(forwarded.ForwardingCopyResult())
		result.cleanup = snapshotCauses(forwarded.ForwardingCleanup())
	case errors.As(cause, &visitor):
		result.service, result.run, result.visitor, result.number = visitor.ForwardingScope()
		result.candidate, result.candidateNumber = visitor.ForwardingCandidate()
		result.phase, result.denial, result.admitted = visitor.ForwardingPhase(), visitor.ForwardingDenialReason(), visitor.ForwardingAdmitted()
		result.operationResult = snapshotCauses(visitor.ForwardingOperation())
		result.copyResult = snapshotCauses(visitor.ForwardingCopyResult())
		result.cleanup = snapshotCauses(visitor.ForwardingCleanup())
	default:
		result.operationResult = result.result
	}
	return result
}

// retain tree positions and exact typed native fields, not Error() strings.
// limits protect observation from an unusually large or cyclic cause graph.
func snapshotCauses(cause error) causeSnapshot {
	var result causeSnapshot
	var walk func(error, int, int)
	walk = func(err error, parent, depth int) {
		if err == nil {
			return
		}
		if len(result.nodes) == 128 || depth == 32 {
			result.truncated = true
			return
		}
		node := causeNode{kind: fmt.Sprintf("%T", err), parent: parent,
			eof: err == io.EOF, canceled: err == context.Canceled, deadline: err == context.DeadlineExceeded, admission: err == ingress.ErrServiceAdmission}
		switch native := err.(type) {
		case *quic.StreamError:
			node.native, node.streamID, node.code, node.remote = "stream", int64(native.StreamID), uint64(native.ErrorCode), native.Remote
		case *quic.ApplicationError:
			node.native, node.code, node.remote = "application", uint64(native.ErrorCode), native.Remote
		case *quic.TransportError:
			node.native, node.code, node.remote = "transport", uint64(native.ErrorCode), native.Remote
		}
		index := len(result.nodes)
		result.nodes = append(result.nodes, node)
		switch wrapper := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapper.Unwrap() {
				if len(result.nodes) == 128 {
					result.truncated = true
					break
				}
				walk(child, index, depth+1)
			}
		case interface{ Unwrap() error }:
			walk(wrapper.Unwrap(), index, depth+1)
		}
	}
	walk(cause, -1, 0)
	return result
}
