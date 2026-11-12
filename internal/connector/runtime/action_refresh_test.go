package runtime

import (
	"fmt"
	"strings"
	"testing"
)

func TestConnectionActionRefreshSourceIsPrivate(t *testing.T) {
	source := GitHubActionsRefresh{Audience: "https://control.example.test", RequestURL: "https://runtime.example.test/private-token-endpoint", RequestToken: "private-runtime-bearer"}
	request := EnvironmentStart{Schema: 1, GitHubActionsRefresh: &source}
	for _, value := range []any{source, &source, request, &request} {
		rendered := fmt.Sprintf("%v %+v %#v", value, value, value)
		for _, secret := range []string{source.RequestURL, source.RequestToken} {
			if strings.Contains(rendered, secret) {
				t.Fatal("private Action source leaked through diagnostics")
			}
		}
	}
	if source.Getenv("GITHUB_ACTIONS") != "true" || source.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != source.RequestURL || source.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != source.RequestToken || source.Getenv("TNL_SERVER") != "" {
		t.Fatal("explicit Action source borrowed ambient process input")
	}
}
