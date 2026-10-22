package readiness

// Outcome is a bounded reason for a publish run readiness observation.
type Outcome string

const (
	Ready                            Outcome = "ready"
	CertificateMissing               Outcome = "certificate_missing"
	ConnectionsMissing               Outcome = "connections_missing"
	CertificateAndConnectionsMissing Outcome = "certificate_and_connections_missing"
	DNSPending                       Outcome = "dns_pending"
	DNSFailed                        Outcome = "dns_failed"
	Error                            Outcome = "error"
)
