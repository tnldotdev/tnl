package state

import (
	"errors"
	"testing"
)

func TestIntegrationFeedbackPolicyCannotEnableAnonymousAuthors(t *testing.T) {
	f := newServiceHTTPFixture(t)
	policy, err := f.database.GetTeamFeedbackPolicy(t.Context(), f.project.ActorID, f.project.TeamID)
	if err != nil || policy.Authors != "signed_in" {
		t.Fatal("new team did not require signed-in authors", policy, err)
	}
	for _, unsupported := range []string{"anyone", "", "anonymous"} {
		if _, err := f.database.SetTeamFeedbackPolicy(t.Context(), f.project.ActorID, f.project.TeamID, unsupported, f.now); !errors.Is(err, ErrAuthorityInvalid) {
			t.Fatal("unsupported author policy accepted", unsupported, err)
		}
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.teams SET feedback_authors='anyone' WHERE id=$1`, f.project.TeamID); err == nil {
		t.Fatal("stored policy accepted anonymous authors")
	}
	for _, authors := range []string{"team_members", "signed_in"} {
		if _, err := f.database.SetTeamFeedbackPolicy(t.Context(), f.project.ActorID, f.project.TeamID, authors, f.now); err != nil {
			t.Fatal(err)
		}
	}
}
