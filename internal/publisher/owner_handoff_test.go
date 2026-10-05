package publisher

import (
	"strings"
	"testing"
	"time"
)

func TestOwnerHandoffIsLocalOneTimeAndExpires(t *testing.T) {
	owner := NewOwnerHandoff()
	if _, err := owner.NewLink("http://app.example.test"); err == nil {
		t.Fatal("owner link accepted non-HTTPS origin")
	}
	link, err := owner.NewLink("https://app.example.test")
	if err != nil || !strings.HasPrefix(link, "https://app.example.test/__tnl/feedback/owner/handoff/") {
		t.Fatalf("owner link = %q, %v", link, err)
	}
	token, found := ownerHandoffToken(strings.TrimPrefix(link, "https://app.example.test"))
	if !found {
		t.Fatal("link has no handoff token")
	}
	session, expires, ok := owner.Redeem(token)
	if !ok || !expires.After(time.Now()) || !owner.ValidSession(session) || session == token {
		t.Fatalf("handoff session = %t, %t, %q", ok, owner.ValidSession(session), session)
	}
	if _, _, ok := owner.Redeem(token); ok {
		t.Fatal("owner handoff was reused")
	}
	if owner.ValidSession(token) {
		t.Fatal("handoff secret was accepted as an owner session")
	}
}
