package visitortoken

import (
	"maps"
	"time"
)

// ApplicationLease is a resource-bound current grant/key projection. it carries
// no signing key or bearer credential, and cannot authorize another operation.
type ApplicationLease struct {
	Subject   Application
	ExpiresAt time.Time
}

func (v View) WithApplicationLeases(leases map[string]ApplicationLease) View {
	v.applications = maps.Clone(leases)
	return v
}

func (v View) ValidApplicationLeases() bool {
	if len(v.applications) > 256 {
		return false
	}
	for id, parent := range v.applications {
		if id != parent.Subject.GrantID || !parent.Subject.valid() || parent.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}
