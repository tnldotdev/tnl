package visitortoken

import (
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

// CheckConnectorPermission checks signed, current connector permission facts.
// it does not prove possession or construct admission evidence. control must
// match these facts to an independently checked admitted connector binding.
func CheckConnectorPermission(token Token, view View, now time.Time) (Permission, error) {
	permission, err := verify(token, view, now)
	if err != nil {
		return Permission{}, err
	}
	if permission.Scope.Kind != visitorscope.Service {
		return Permission{}, ErrBinding
	}
	if _, err := ConnectorSubject(permission.Subject); err != nil {
		return Permission{}, err
	}
	return permission, nil
}
