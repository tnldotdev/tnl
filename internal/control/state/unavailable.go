package state

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsUnavailable identifies known database transport and temporary admission
// failures. callers keep unknown faults internal; a joined independent fault
// does not become unavailable merely because another cause is temporary.
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	switch err {
	case context.DeadlineExceeded, os.ErrDeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, net.ErrClosed,
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE,
		syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !IsUnavailable(cause) {
				return false
			}
		}
		return true
	}
	switch cause := err.(type) {
	case *pgconn.PgError:
		if cause != nil {
			// do not classify protocol violations or connection configuration
			// errors as temporary merely because they share SQLSTATE class 08.
			switch cause.Code {
			case "08000", "08001", "08003", "08006", "53300", "57P01", "57P02", "57P03":
				return true
			}
		}
		return false
	}
	if cause := errors.Unwrap(err); cause != nil {
		return IsUnavailable(cause)
	}
	if dns, ok := err.(*net.DNSError); ok && dns != nil {
		return dns.IsTimeout || dns.IsTemporary || dns.IsNotFound
	}
	return false
}
