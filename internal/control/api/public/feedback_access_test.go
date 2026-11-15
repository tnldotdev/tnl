package public

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestFeedbackVisitProofDecodingKeepsVisitAndAuthorSeparate(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, raw := range []string{
		`{"kind":"bearer","token":"private-bearer"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"7","permission_token":"private-connector"}`,
	} {
		actor, err := feedbackReviewerActor(controlv1.FeedbackReviewerAccess{
			VisitProof: json.RawMessage(raw), BrowserCookieSecret: &secret,
		})
		if err != nil || actor.VisitProof == nil || actor.IdentityID != "" || actor.DisplayName != "" ||
			actor.VisitAllowed || len(actor.BrowserCookieSecret) != 32 {
			t.Fatal("proof decoding fabricated visit permission or author identity", err)
		}
		switch proof := actor.VisitProof.(type) {
		case controlstate.FeedbackBearerVisitProof:
			if proof.Token.Reveal() != "private-bearer" {
				t.Fatal("selected bearer proof changed")
			}
		case controlstate.FeedbackConnectorVisitProof:
			if proof.PairID != "cpp_1111111111111111111111" || proof.DeliveryGeneration != 7 || proof.PermissionToken.Reveal() != "private-connector" {
				t.Fatal("admitted connector proof changed")
			}
		default:
			t.Fatal("proof decoding created an unsupported authority source")
		}
		if formatted := fmt.Sprintf("%v %+v %#v", actor.VisitProof, actor.VisitProof, actor.VisitProof); strings.Contains(formatted, "private-") {
			t.Fatal("proof formatting exposed a selected credential")
		}
	}
}

func TestFeedbackExplicitInvalidProofCannotFallBackToAnonymous(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `[]`, `""`, `{"kind":null}`, `{"kind":"certificate","token":"private"}`,
		`{"kind":"bearer","token":null}`, `{"kind":"bearer","token":""}`,
		`{"kind":"bearer","token":"private","pair_id":"cpp_1111111111111111111111"}`,
		`{"kind":"bearer","token":"private"} {}`,
		`{"kind":"bearer","token":"` + strings.Repeat("x", 2049) + `"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"0","permission_token":"private"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"01","permission_token":"private"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"+1","permission_token":"private"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":1,"permission_token":"private"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"9223372036854775808","permission_token":"private"}`,
		`{"kind":"connector","pair_id":"another","delivery_generation":"1","permission_token":"private"}`,
		`{"kind":"connector","pair_id":"cpp_1111111111111111111111","delivery_generation":"1","permission_token":"private","token":"other"}`,
	} {
		_, err := feedbackReviewerActor(controlv1.FeedbackReviewerAccess{VisitAllowed: true, VisitProof: json.RawMessage(raw)})
		if !errors.Is(err, controlstate.ErrFeedbackAccess) {
			t.Fatal("invalid explicit proof fell back to observational visit_allowed", err)
		}
	}
	var explicit, omitted controlv1.FeedbackReviewerAccess
	if err := json.Unmarshal([]byte(`{"visit_allowed":true,"visit_proof":null}`), &explicit); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"visit_allowed":true}`), &omitted); err != nil {
		t.Fatal(err)
	}
	if explicit.VisitProof == nil || omitted.VisitProof != nil {
		t.Fatal("wire decoding erased the difference between absent and invalid proof")
	}
	if _, err := feedbackReviewerActor(explicit); !errors.Is(err, controlstate.ErrFeedbackAccess) {
		t.Fatal("explicit null became anonymous access", err)
	}
	if actor, err := feedbackReviewerActor(omitted); err != nil || actor.VisitProof != nil {
		t.Fatal("ordinary proof-free observation changed", err)
	}
}

func TestFeedbackExplicitShareCredentialsRemainCompleteAndExclusive(t *testing.T) {
	id := "shr_1111111111111111111111"
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, access := range []controlv1.FeedbackReviewerAccess{
		{ShareId: &id}, {CookieSecret: &secret}, {ShareSecret: &secret},
		{ShareId: &id, CookieSecret: &secret, ShareSecret: &secret},
		{ShareId: &id, CookieSecret: new("invalid")},
		{ShareId: &id, CookieSecret: &secret, VisitProof: json.RawMessage(`{"kind":"bearer","token":"private"}`)},
		{BrowserCookieSecret: new("invalid"), VisitProof: json.RawMessage(`{"kind":"bearer","token":"private"}`)},
	} {
		access.VisitAllowed = true
		if _, err := feedbackReviewerActor(access); !errors.Is(err, controlstate.ErrFeedbackAccess) {
			t.Fatal("incomplete or conflicting explicit credentials fell back", err)
		}
	}
	for _, access := range []controlv1.FeedbackReviewerAccess{
		{ShareId: &id, CookieSecret: &secret}, {ShareId: &id, ShareSecret: &secret},
	} {
		if actor, err := feedbackReviewerActor(access); err != nil || actor.ShareID != id ||
			(len(actor.CookieSecret) == 32) == (len(actor.ShareSecret) == 32) {
			t.Fatal("ordinary share credential changed", err)
		}
	}
}
