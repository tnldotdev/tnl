//go:build tnl_benchtrace

package service

// DiagnosticVisitorConnectionID exposes only the already validated wire ID.
// admission state belongs to Bound.mu; this getter neither checks nor grants use.
func (a *connectorAdmission) DiagnosticVisitorConnectionID() string {
	if a == nil || a.peer == nil || a.peer.bound == nil {
		return ""
	}
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	if !a.admitted {
		return ""
	}
	return a.entry.VisitorConnectionID
}
