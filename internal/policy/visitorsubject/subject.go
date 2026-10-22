// package visitorsubject converts the tagged visitor principal at HTTP boundaries.
package visitorsubject

import (
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func Wire(s tunnelv1.VisitorSubject) controlv1.VisitorSubject {
	r := controlv1.VisitorSubject{Kind: controlv1.VisitorSubjectKind(s.Kind)}
	if s.IdentityID != "" {
		r.IdentityId = new(s.IdentityID)
	}
	if s.DeviceID != "" {
		r.DeviceId = new(s.DeviceID)
	}
	if s.WorkloadSessionID != "" {
		r.WorkloadSessionId = new(s.WorkloadSessionID)
	}
	return r
}

// Parse rejects even empty fields belonging to another variant.
func Parse(s controlv1.VisitorSubject) (tunnelv1.VisitorSubject, error) {
	r := tunnelv1.VisitorSubject{Kind: string(s.Kind)}
	if s.IdentityId != nil {
		r.IdentityID = *s.IdentityId
	}
	if s.DeviceId != nil {
		r.DeviceID = *s.DeviceId
	}
	if s.WorkloadSessionId != nil {
		r.WorkloadSessionID = *s.WorkloadSessionId
	}
	if r.Kind == tunnelv1.VisitorHumanDevice && (s.IdentityId == nil || s.DeviceId == nil || s.WorkloadSessionId != nil) ||
		r.Kind == tunnelv1.VisitorWorkloadSession && (s.WorkloadSessionId == nil || s.IdentityId != nil || s.DeviceId != nil) {
		return tunnelv1.VisitorSubject{}, tunnelv1.ErrInvalidVisitorSubject
	}
	return r, r.Validate()
}

func Equal(w controlv1.VisitorSubject, s tunnelv1.VisitorSubject) bool {
	parsed, err := Parse(w)
	return err == nil && parsed == s
}

func Same(a, b controlv1.VisitorSubject) bool {
	s, err := Parse(b)
	return err == nil && Equal(a, s)
}
