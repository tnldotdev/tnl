package main

import (
	"io"
	"testing"
)

func TestTeamFeedbackPolicyRequiresSignedInAuthors(t *testing.T) {
	for _, authors := range []string{"anyone", "signed_in", "team_members"} {
		t.Run(authors, func(t *testing.T) {
			var flags cli
			parser := commandForTest(&flags, io.Discard)
			_, err := parser([]string{"team", "feedback", "set", authors})
			if authors == "anyone" {
				if err == nil {
					t.Fatal("CLI retained anonymous feedback policy")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
