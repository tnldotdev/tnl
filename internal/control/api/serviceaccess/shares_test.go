package serviceaccess

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestShareProjectionKeepsCanonicalCaptureAndCreationOnlySecret(t *testing.T) {
	now := time.Now().UTC()
	record := controlstate.Share{
		SchemaVersion: 1, ID: "shr_example", TeamID: "team", CreatedByIdentityID: "identity",
		Scope: "service", Label: "review", ServiceIDs: []string{"svc_example"}, EntryServiceID: "svc_example",
		EntryHostname: "web.example.test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	const secret = "creation-only-secret"
	created := ShareCreation(record, secret)
	if created.Share.Id != record.ID || created.Share.Scope != controlv1.ShareScopeService ||
		!slices.Equal(created.Share.ServiceIds, record.ServiceIDs) || created.Share.EntryServiceId != record.EntryServiceID ||
		created.TokenSource.Kind != controlv1.VisitorTokenShare || created.TokenSource.ShareId != record.ID ||
		created.TokenSource.Secret != secret || created.Link != "https://web.example.test/__tnl/share/"+record.ID+"."+secret {
		t.Fatal("creation changed its canonical captured service or credential")
	}
	page := SharePage(controlstate.SharePage{Shares: []controlstate.Share{record}, NextCursor: record.ID})
	if page.SchemaVersion != 1 || len(page.Shares) != 1 || page.NextCursor == nil || *page.NextCursor != record.ID ||
		!page.Shares[0].ExpiresAt.Equal(record.ExpiresAt) || page.Shares[0].CreatedByIdentityId != record.CreatedByIdentityID {
		t.Fatal("share page changed its owner, deadline or cursor")
	}
	for _, value := range []any{Share(record), page} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{secret, "token_source", "fingerprint", "secret_digest", "entry_hostname"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("share read exposed creation-only or internal material", forbidden)
			}
		}
	}
	empty, err := json.Marshal(SharePage(controlstate.SharePage{}))
	if err != nil || !strings.Contains(string(empty), `"shares":[]`) {
		t.Fatal("empty share page lost its array", err)
	}
}

func TestShareProjectionPreservesPreviewAndGuestOwnership(t *testing.T) {
	preview := Share(controlstate.Share{SchemaVersion: 1, ID: "share", Scope: "preview", PreviewID: "preview",
		TeamID: "team", CreatedByIdentityID: "creator", ServiceIDs: []string{"one", "two"}, EntryServiceID: "two"})
	if preview.PreviewId == nil || *preview.PreviewId != "preview" || len(preview.ServiceIds) != 2 || preview.GuestId != "" {
		t.Fatal("preview projection replaced its captured services or owner")
	}
	guest := Share(controlstate.Share{SchemaVersion: 1, ID: "share", Scope: "guest", GuestID: "guest",
		ServiceIDs: []string{"demo"}, EntryServiceID: "demo"})
	if guest.GuestId != "guest" || guest.TeamId != "" || guest.CreatedByIdentityId != "" || guest.PreviewId != nil {
		t.Fatal("guest share acquired a human, team or preview owner")
	}
}
