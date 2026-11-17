package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDatabaseUnavailabilityRequiresEveryIndependentCause(t *testing.T) {
	outage := &pgconn.PgError{Code: "57P03"}
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{outage, true},
		{fmt.Errorf("query: %w", outage), true},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, true},
		{&pgconn.PgError{Code: "08006"}, true},
		{&pgconn.PgError{Code: "53300"}, true},
		{&pgconn.PgError{Code: "08"}, false},
		{&pgconn.PgError{Code: "08P01"}, false},
		{&pgconn.PgError{Code: "08004"}, false},
		{&net.OpError{Op: "read", Net: "tcp", Err: errors.Join(syscall.ECONNRESET, errors.New("independent fault"))}, false},
		{&net.OpError{Op: "read", Net: "tcp", Err: errors.New("unexpected implementation fault")}, false},
		{&pgconn.PgError{Code: "28P01"}, false},
		{&pgconn.PgError{Code: "23514"}, false},
		{errors.New("database unavailable"), false},
		{context.Canceled, false},
		{errors.Join(outage, errors.New("independent fault")), false},
		{errors.Join(outage, &pgconn.PgError{Code: "57P01"}), true},
	} {
		if got := IsUnavailable(test.err); got != test.want {
			t.Errorf("known unavailable=%t want=%t for %T", got, test.want, test.err)
		}
	}
}
