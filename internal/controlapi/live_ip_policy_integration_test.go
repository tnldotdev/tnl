package controlapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationLiveVisitorIPAPIRequiresEditorAndKeepsRun(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{})
	base := "/v1/public-urls/" + f.publicURL.ID
	owner := f.owner.AccessToken.String()
	f.call(http.MethodPut, base+"/ip-policy", `{"allowed_ip_prefixes":["192.0.2.7"]}`, "", "", http.StatusUnauthorized)
	f.call(http.MethodPut, base+"/ip-policy", `{"allowed_ip_prefixes":["192.0.2.7"]}`, "pta_machine", "", http.StatusUnauthorized)
	changed := f.call(http.MethodPut, base+"/ip-policy", `{"allowed_ip_prefixes":["192.0.2.7"]}`, owner, "", http.StatusOK)
	var route controlv1.PublicURL
	if err := json.Unmarshal(changed.Body.Bytes(), &route); err != nil || route.AllowedIpPrefixes == nil ||
		len(*route.AllowedIpPrefixes) != 1 || (*route.AllowedIpPrefixes)[0] != "192.0.2.7/32" {
		t.Fatalf("live source policy = %s, %v", changed.Body.String(), err)
	}
	created := f.call(http.MethodPost, base+"/ip-entries", `{"prefix":"198.51.100.10","expires_in_seconds":3600}`, owner, "", http.StatusCreated)
	var entry controlv1.OperatorIPEntry
	if err := json.Unmarshal(created.Body.Bytes(), &entry); err != nil || entry.Id == "" || entry.Prefix != "198.51.100.10/32" || entry.OwnerId != f.membership.IdentityID {
		t.Fatalf("operator entry = %s, %v", created.Body.String(), err)
	}
	f.call(http.MethodPost, base+"/ip-entries", `{"prefix":"203.0.113.7","expires_in_seconds":3600}`, "pta_machine", "", http.StatusUnauthorized)
	listed := f.call(http.MethodGet, base+"/ip-entries", "", owner, "", http.StatusOK)
	var page struct {
		Entries []controlv1.OperatorIPEntry `json:"entries"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil || len(page.Entries) != 1 || page.Entries[0].Id != entry.Id {
		t.Fatalf("operator entries = %s, %v", listed.Body.String(), err)
	}
	f.call(http.MethodDelete, base+"/ip-entries/"+entry.Id, "", owner, "", http.StatusNoContent)
	listed = f.call(http.MethodGet, base+"/ip-entries", "", owner, "", http.StatusOK)
	if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil || len(page.Entries) != 0 {
		t.Fatalf("operator entries after revocation = %s, %v", listed.Body.String(), err)
	}
	current, err := f.database.GetPublicURLForAuthorization(t.Context(), f.publicURL.ID)
	if err != nil || current.OpenPublishRunID != f.run.PublishRunID {
		t.Fatalf("live IP edits replaced the open publish run: %v", err)
	}
}
