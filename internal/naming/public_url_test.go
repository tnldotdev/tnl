package naming

import "testing"

func TestHTTPSOrigin(t *testing.T) {
	for _, test := range []struct {
		hostname string
		port     int
		want     string
	}{
		{"app.example.com", 25443, "https://app.example.com:25443"},
		{"app.example.com", 443, "https://app.example.com:443"},
		{"app.example.com", 0, ""},
		{"app.example.com", -1, ""},
		{"app.example.com", 65536, ""},
		{"APP.example.com", 25443, ""},
		{"app.example.com:25443", 25443, ""},
		{"", 25443, ""},
	} {
		if got := HTTPSOrigin(test.hostname, test.port); got != test.want {
			t.Fatalf("HTTPSOrigin(%q, %d) = %q, want %q", test.hostname, test.port, got, test.want)
		}
	}
}

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
