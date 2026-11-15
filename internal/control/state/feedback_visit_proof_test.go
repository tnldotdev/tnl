package state

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestFeedbackVisitProofFormattingRedactsCredentials(t *testing.T) {
	for _, proof := range []FeedbackVisitProof{
		FeedbackBearerVisitProof{Token: visitortoken.Token("private-bearer")},
		FeedbackConnectorVisitProof{PairID: "private-pair", DeliveryGeneration: 1, PermissionToken: "private-connector"},
	} {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, proof), "private") {
				t.Fatal("feedback proof formatting exposed a credential or binding")
			}
		}
	}
}
