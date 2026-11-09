package visitortoken

import (
	"crypto/subtle"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func (v View) possession(subject Subject) ([32]byte, time.Time, bool) {
	switch source := subject.(type) {
	case Share:
		verifier, found := v.shares[source.ShareID]
		return verifier.Digest, verifier.ExpiresAt, found && v.Scope.Kind == visitorscope.PublicURL
	case Grant:
		verifier, found := v.grants[source.GrantID]
		return verifier.Digest, verifier.ExpiresAt, found && source.valid() && verifier.Kind == source.Kind && v.Scope.Kind == visitorscope.Service
	default:
		return [32]byte{}, time.Time{}, false
	}
}

func verifyPossession(subject Subject, digest [32]byte, view View, now time.Time) (VerifiedPermission, error) {
	_, until, _ := view.possession(subject)
	permission := VerifiedPermission{facts: Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: subject, ExpiresAt: until}, bearerDigest: digest}
	if err := checkPossessionCurrent(permission, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	return permission, nil
}

func checkPossessionCurrent(permission VerifiedPermission, view View, now time.Time) error {
	if !view.current(now) {
		return ErrPolicy
	}
	facts := permission.facts
	digest, until, found := view.possession(facts.Subject)
	if !found || facts.Scope != view.Scope || facts.Hostname != view.Hostname || facts.Port != view.Port || permission.bearerDigest == ([32]byte{}) ||
		subtle.ConstantTimeCompare(permission.bearerDigest[:], digest[:]) != 1 || !facts.ExpiresAt.After(view.AuthorityTime(now)) || !until.After(view.AuthorityTime(now)) {
		return ErrToken
	}
	return nil
}

// PermissionDeadline preserves the admitted credential's lifetime while applying
// a shorter current parent deadline. policy renewal never widens an admission.
func PermissionDeadline(permission VerifiedPermission, view View) time.Time {
	until := permission.facts.ExpiresAt
	if application, ok := permission.facts.Subject.(Application); ok {
		if parent, found := view.applications[application.GrantID]; found && parent.ExpiresAt.Before(until) {
			until = parent.ExpiresAt
		}
	}
	if permission.bearerDigest != ([32]byte{}) {
		if _, parent, found := view.possession(permission.facts.Subject); found && parent.Before(until) {
			until = parent
		}
	}
	return until
}
