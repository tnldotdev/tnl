package controlstate

// PublicURLPurpose is the immutable, client-declared use of a saved public URL.
type PublicURLPurpose string

const (
	PublicURLPurposeApp      PublicURLPurpose = "app"
	PublicURLPurposeAlias    PublicURLPurpose = "alias"
	PublicURLPurposeDemo     PublicURLPurpose = "demo"
	PublicURLPurposeOAuth    PublicURLPurpose = "oauth"
	PublicURLPurposeWebhooks PublicURLPurpose = "webhooks"
)

func (p PublicURLPurpose) ValidForCreation() bool {
	switch p {
	case PublicURLPurposeApp, PublicURLPurposeAlias, PublicURLPurposeDemo, PublicURLPurposeOAuth, PublicURLPurposeWebhooks:
		return true
	}
	return false
}
