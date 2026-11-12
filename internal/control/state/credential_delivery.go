package state

// an authorized exact creation retry cannot redeliver its original credential.
// only a digest is retained, so the original credential cannot be delivered again.
type CredentialDeliveryUnavailable struct {
	ResourceID string
}

func (*CredentialDeliveryUnavailable) Error() string {
	return "controlstate: credential delivery unavailable; revoke and reissue"
}
