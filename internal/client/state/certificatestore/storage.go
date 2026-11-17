// package certificatestore owns durable publisher certificate transitions.
// native client state and host adapters supply protected storage; this package
// owns key creation, validation, plan checkpoints and pending/staged/current
// recovery. it starts no workers and never grants publication authority.
// it depends on validated shared values and the control contract, not native
// state or publisher composition. the parent state package owns SQLite and
// private filesystem lifetimes that a host-backed cache must not import.
package certificatestore

import (
	"context"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/failure"
)

// Scope is the exact ownership recorded inside every certificate snapshot.
// the storage supplied to New must be isolated to these same values.
type Scope struct {
	ControlURL          string `json:"control_url"`
	TeamID              string `json:"team_id"`
	PublisherIdentityID string `json:"publisher_identity_id"`
}

// Storage persists small private records in one publisher identity scope.
// implementations must protect confidentiality and reject replaced owners.
//
// reads return owned bytes from one complete atomic snapshot, bounded by limit.
// writes atomically replace the entire record and return success only after it
// is durable. an error may leave the old or new complete record. Sync must make
// a recovered uncertain write durable before its key or certificate is exposed.
//
// Lock is exclusive across every instance sharing the scope, not just one Go
// process. named locks are independent and non-reentrant; Close releases exactly
// that acquisition and reports release failures. mutation locks must not expire
// while their owner can still write.
//
// asynchronous hosts may await a bridge operation in each method. cancellation
// must join it before return: no pending write or lock acquisition may continue
// afterward, and an acquired lock must be released if cancellation wins.
// unavailable storage should return failure.PublisherIdentityStateUnavailable;
// invalid, missing-checkpoint or unprotected state must fail closed.
type Storage interface {
	Read(context.Context, string, int64) ([]byte, bool, error)
	Write(context.Context, string, []byte) error
	Sync(context.Context, string) error
	Lock(context.Context, string) (io.Closer, error)
}

var ErrPublisherStateConflict = errors.New("clientstate: publisher identity or enrollment changed")

func identityFileError(err error) error {
	if err == nil {
		return nil
	}
	if _, typed := failure.Of(err); typed {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return failure.Wrap("use durable publisher identity files", failure.PublisherIdentityStateInvalid, err)
}
