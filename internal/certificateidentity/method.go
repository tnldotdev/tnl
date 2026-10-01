package certificateidentity

// ChallengeMethod is the certificate challenge selected by the authority.
type ChallengeMethod string

const (
	ChallengeDNS01     ChallengeMethod = "dns-01"
	ChallengeTLSALPN01 ChallengeMethod = "tls-alpn-01"
)

func (method ChallengeMethod) Valid() bool {
	return method == ChallengeDNS01 || method == ChallengeTLSALPN01
}
