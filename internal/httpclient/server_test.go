package httpclient

import "testing"

func TestCanonicalServerRejectsNonOrigins(t *testing.T) {
	for _, value := range []string{"http://tnl.example", "https://user@tnl.example", "https://tnl.example/path", "https://tnl.example?query=true", "https://tnl.example:0", "https://tnl.example:65536"} {
		if _, err := CanonicalServer(value); err == nil {
			t.Fatalf("CanonicalServer(%q) succeeded", value)
		}
	}
	if got, err := CanonicalServer("https://TNL.EXAMPLE:443/"); err != nil || got != "https://tnl.example" {
		t.Fatalf("canonical server = %q, %v", got, err)
	}
}
