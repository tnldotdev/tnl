package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// RequestLimits is the run-owned request budget, shared across visitor streams.
// the service run supplies it; a stream never creates a separate budget.
type RequestLimits interface {
	Admit(http.ResponseWriter, *http.Request) (func(), bool)
	Limits() applicationlimits.Limits
}

func targetConnections(limits RequestLimits) int {
	if limits == nil {
		return applicationlimits.Limits{}.Defaults(false).Concurrency
	}
	return limits.Limits().Concurrency
}

func admitRequest(limits RequestLimits, w http.ResponseWriter, r *http.Request) (func(), bool) {
	if limits == nil {
		return func() {}, true
	}
	return limits.Admit(w, r)
}

func DenyHTTP(w http.ResponseWriter, r *http.Request, status int) {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	switch status {
	case http.StatusForbidden:
		diagnostic.WriteHTTP(w, r, diagnostic.VisitorAccessDenied, "")
		return
	case http.StatusMisdirectedRequest:
		diagnostic.WriteHTTP(w, r, diagnostic.RequestMisdirected, "")
		return
	}
	message := "service HTTP access denied"
	if status == http.StatusServiceUnavailable {
		message = "service HTTP authorization is unavailable; retry"
	} else if status == http.StatusInternalServerError {
		message = "service HTTP authorization failed"
	}
	http.Error(w, message, status)
}

func HTTPDecisionStatus(err error) int {
	return httpDecisionStatus(err, false)
}

// classify each independent cause. a denial or unavailable marker must not hide
// an unrelated fault in a joined result, even beneath a diagnostic wrapper.
func httpDecisionStatus(err error, denied bool) int {
	switch err {
	case nil, visitortoken.ErrToken, visitortoken.ErrBinding, clientcontrol.ErrNotFound,
		clientcontrol.ErrUnauthenticated, clientcontrol.ErrStatusConflict:
		return http.StatusForbidden
	case clientcontrol.ErrUnavailable, visitortoken.ErrKey:
		return http.StatusServiceUnavailable
	case os.ErrDeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, net.ErrClosed,
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE,
		syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
		return http.StatusServiceUnavailable
	case visitortoken.ErrPolicy, context.Canceled, context.DeadlineExceeded:
		if denied {
			return http.StatusForbidden
		}
		return http.StatusServiceUnavailable
	}
	if _, ok := err.(*diagnostic.Error); ok {
		if code, _ := diagnostic.CodeOf(err); code == diagnostic.VisitorAccessDenied {
			denied = true
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return http.StatusInternalServerError
		}
		status := http.StatusForbidden
		for _, cause := range causes {
			current := httpDecisionStatus(cause, denied)
			if current == http.StatusInternalServerError {
				return current
			}
			if current == http.StatusServiceUnavailable {
				status = current
			}
		}
		return status
	}
	if problem, ok := err.(*clientcontrol.ProblemError); ok && problem != nil {
		switch problem.Status {
		case 401, 403, 404, 409:
			return http.StatusForbidden
		case 502, 503, 504:
			switch problem.Problem.Code {
			case controlv1.Unavailable, controlv1.PlacementUnavailable, controlv1.CredentialDeliveryUnavailable:
				return http.StatusServiceUnavailable
			}
		}
		return http.StatusInternalServerError
	}
	if cause := errors.Unwrap(err); cause != nil {
		return httpDecisionStatus(cause, denied)
	}
	if dns, ok := err.(*net.DNSError); ok && dns != nil && (dns.IsTimeout || dns.IsTemporary || dns.IsNotFound) {
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}
