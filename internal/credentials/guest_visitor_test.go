package credentials

import "testing"

func TestGuestVisitorTokenCannotAuthorizeAnotherURL(t *testing.T) {
	token, _, hash, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := GuestVisitorToken(token, "gst_guest", "url_first")
	if err != nil || !GuestVisitorTokenMatches(visitor, "gst_guest", "url_first", hash[:]) {
		t.Fatalf("guest visitor token failed for its URL: %v", err)
	}
	if GuestVisitorTokenMatches(visitor, "gst_guest", "url_second", hash[:]) ||
		GuestVisitorTokenMatches(visitor, "gst_other", "url_first", hash[:]) ||
		GuestVisitorTokenMatches(token.String(), "gst_guest", "url_first", hash[:]) {
		t.Fatal("guest publisher credential or another URL authorized a visitor")
	}
}
