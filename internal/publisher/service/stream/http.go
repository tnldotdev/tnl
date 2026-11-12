package stream

import (
	"errors"
	"net/http"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// RequestLimits is the run-owned request budget, shared across visitor streams.
// the service run supplies it; a stream never creates a separate budget.
type RequestLimits interface {
	Admit(http.ResponseWriter, *http.Request) (func(), bool)
}

func admitRequest(limits RequestLimits, w http.ResponseWriter, r *http.Request) (func(), bool) {
	if limits == nil {
		return func() {}, true
	}
	return limits.Admit(w, r)
}

func DenyHTTP(w http.ResponseWriter, status int) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	message := "service HTTP access denied"
	if status == http.StatusServiceUnavailable {
		message = "service HTTP authorization is unavailable; retry"
	}
	http.Error(w, message, status)
}

func HTTPDecisionStatus(err error) int {
	if err == nil || errors.Is(err, visitortoken.ErrToken) || errors.Is(err, visitortoken.ErrBinding) || errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrStatusConflict) {
		return http.StatusForbidden
	}
	var problem *clientcontrol.ProblemError
	if errors.As(err, &problem) && problem != nil && (problem.Status == 401 || problem.Status == 403 || problem.Status == 404 || problem.Status == 409) {
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}
