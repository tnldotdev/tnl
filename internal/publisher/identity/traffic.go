package identity

import "github.com/tnldotdev/tnl/internal/policy/trafficlimits"

// WithTraffic makes an independent worker selection without changing the
// original adapter or retaining caller-owned pointers.
func (n *Native) WithTraffic(selection *trafficlimits.Selection) (*Native, error) {
	if n == nil {
		return nil, ErrScope
	}
	copy := *n
	copy.private = append(copy.private[:0:0], n.private...)
	copy.publicURL = clonePublicURL(n.publicURL)
	copy.environmentPublication = cloneEnvironmentPublication(n.environmentPublication)
	copy.traffic = nil
	if selection == nil {
		return &copy, nil
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	copy.traffic = selection.Clone()
	return &copy, nil
}
