package controlstate

import (
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// connection configuration, connection lifecycle, admission history, and owner
// decisions are independent domains even where their stored strings coincide.
type companyAdmissionMode string
type identityConnectionState string
type companyAdmissionRequestState string
type companyOwnerAdmissionDecision string

const (
	companyAdmissionApproval  companyAdmissionMode    = "approval"
	companyAdmissionManaged   companyAdmissionMode    = "managed"
	identityConnectionPending identityConnectionState = "pending"
	identityConnectionActive  identityConnectionState = "active"
	identityConnectionRetired identityConnectionState = "retired"

	companyRequestPending  companyAdmissionRequestState = "pending"
	companyRequestApproved companyAdmissionRequestState = "approved"
	companyRequestDenied   companyAdmissionRequestState = "denied"

	companyOwnerApprove companyOwnerAdmissionDecision = "approved"
	companyOwnerDeny    companyOwnerAdmissionDecision = "denied"
)

func parseCompanyAdmissionMode(value string) (companyAdmissionMode, error) {
	mode := companyAdmissionMode(value)
	if mode != companyAdmissionApproval && mode != companyAdmissionManaged {
		return "", ErrAuthorityInvalid
	}
	return mode, nil
}

func parseCompanyOwnerAdmissionDecision(value string) (companyOwnerAdmissionDecision, error) {
	decision := companyOwnerAdmissionDecision(value)
	if decision != companyOwnerApprove && decision != companyOwnerDeny {
		return "", ErrAuthorityInvalid
	}
	return decision, nil
}

// owners may retry or revise a decision. request state is history, not an owner
// command; even a repeated approval must recheck current source eligibility.
func (state companyAdmissionRequestState) decide(decision companyOwnerAdmissionDecision) (companyAdmissionRequestState, error) {
	if state != companyRequestPending && state != companyRequestApproved && state != companyRequestDenied {
		return "", ErrAuthorityConflict
	}
	switch decision {
	case companyOwnerApprove:
		return companyRequestApproved, nil
	case companyOwnerDeny:
		return companyRequestDenied, nil
	default:
		return "", ErrAuthorityInvalid
	}
}

type companyConnection struct {
	controlstatedb.ControlIdentityConnection
	admission companyAdmissionMode
	state     identityConnectionState
}

func companyConnectionFromRow(row controlstatedb.ControlIdentityConnection) companyConnection {
	return companyConnection{ControlIdentityConnection: row, admission: companyAdmissionMode(row.Admission), state: identityConnectionState(row.State)}
}

func (c companyConnection) acceptsProvisioning(now time.Time) bool {
	return c.state == identityConnectionActive || c.state == identityConnectionPending && c.SetupExpiresAt.Time.After(now)
}

func (c companyConnection) automaticallyAdmits() bool {
	return c.admission == companyAdmissionManaged && c.state == identityConnectionActive
}

// suspension and a personal-account exception remain independent: an exception
// never unsuspends a member, including when both are explicitly set together.
type CompanyMembershipDecision struct {
	Suspended                bool
	PersonalAccountException bool
}
