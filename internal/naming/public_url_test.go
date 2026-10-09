package naming

import "testing"

func TestParseExactPublicURL(t *testing.T) {
	for _, value := range []string{"app.example.com", "https://app.example.com"} {
		hostname, err := ParseExactPublicURL(value)
		if err != nil || hostname != "app.example.com" {
			t.Fatalf("%q = %q, %v", value, hostname, err)
		}
	}
	for _, value := range []string{
		"app", "", "APP.example.com", "app.example.com.", " app.example.com", "http://app.example.com",
		"https://app.example.com:443", "app.example.com/path", "https://app.example.com/",
		"app.example.com?x=1", "app.example.com#part", "https://user@app.example.com", "127.0.0.1",
	} {
		if hostname, err := ParseExactPublicURL(value); err == nil {
			t.Fatalf("accepted %q as %q", value, hostname)
		}
	}
}
