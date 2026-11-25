package naming

import (
	"strings"
	"testing"
)

func TestParseServiceSelector(t *testing.T) {
	const id = "svc_0123456789ABCDefghijkl"
	tests := []struct {
		input string
		want  ServiceSelector
	}{
		{"", ServiceSelector{Kind: SelectorOmitted}},
		{"api-2", ServiceSelector{Kind: SelectorName, Name: "api-2"}},
		{id, ServiceSelector{Kind: SelectorID, ID: id}},
		{"api.", ServiceSelector{Kind: SelectorAddress, Host: "api"}},
		{"API.Example.", ServiceSelector{Kind: SelectorAddress, Host: "api.example"}},
		{"api:8443", ServiceSelector{Kind: SelectorAddress, Host: "api", Port: 8443, ExplicitPort: true}},
		{"api.example:443", ServiceSelector{Kind: SelectorAddress, Host: "api.example", Port: 443, ExplicitPort: true}},
		{"127.0.0.1", ServiceSelector{Kind: SelectorAddress, Host: "127.0.0.1"}},
		{"127.0.0.1:65432", ServiceSelector{Kind: SelectorAddress, Host: "127.0.0.1", Port: 65432, ExplicitPort: true}},
		{"2001:0db8::1", ServiceSelector{Kind: SelectorAddress, Host: "2001:db8::1"}},
		{"[::1]", ServiceSelector{Kind: SelectorAddress, Host: "::1"}},
		{"[2001:0db8::1]:65535", ServiceSelector{Kind: SelectorAddress, Host: "2001:db8::1", Port: 65535, ExplicitPort: true}},
		{"http://api", ServiceSelector{Kind: SelectorAddress, Host: "api", Scheme: "http", Protocol: "http", Port: 80}},
		{"HTTPS://API.EXAMPLE./", ServiceSelector{Kind: SelectorAddress, Host: "api.example", Scheme: "https", Protocol: "http", Port: 443, EscapedPath: "/"}},
		{"https://[2001:db8::1]:443", ServiceSelector{Kind: SelectorAddress, Host: "2001:db8::1", Scheme: "https", Protocol: "http", Port: 443, ExplicitPort: true}},
		{"postgres://db.example", ServiceSelector{Kind: SelectorAddress, Host: "db.example", Scheme: "postgres", Protocol: "postgres", Port: 5432}},
		{"postgresql://db.example:15432", ServiceSelector{Kind: SelectorAddress, Host: "db.example", Scheme: "postgresql", Protocol: "postgres", Port: 15432, ExplicitPort: true}},
		{"mysql://db.example/", ServiceSelector{Kind: SelectorAddress, Host: "db.example", Scheme: "mysql", Protocol: "mysql", Port: 3306}},
		{"tcp://[::1]:9000", ServiceSelector{Kind: SelectorAddress, Host: "::1", Scheme: "tcp", Protocol: "tcp", Port: 9000, ExplicitPort: true}},
		{"kubernetes://cluster.example", ServiceSelector{Kind: SelectorAddress, Host: "cluster.example", Scheme: "kubernetes", Protocol: "kubernetes", Port: 6443}},
		{"kubernetes://cluster.example:443", ServiceSelector{Kind: SelectorAddress, Host: "cluster.example", Scheme: "kubernetes", Protocol: "kubernetes", Port: 443, ExplicitPort: true}},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseServiceSelector(test.input)
			if err != nil || got != test.want {
				t.Fatalf("got %#v, %v; want %#v", got, err, test.want)
			}
		})
	}
}

func TestServiceSelectorResource(t *testing.T) {
	for _, test := range []struct {
		input, path, query string
		forceQuery         bool
	}{
		{"https://api.example/a%2fb?x=%2F+%20&x=1", "/a%2fb", "x=%2F+%20&x=1", false},
		{"https://api.example/%2f", "/%2f", "", false},
		{"https://api.example/?", "/", "", true},
		{"https://api.example?", "", "", true},
		{"https://api.example?key=%23", "", "key=%23", false},
		{"postgresql://db.example/orders?hostaddr=127.0.0.1&sslmode=disable", "", "", false},
		{"mysql://db.example/orders", "", "", false},
		{"tcp://api.example:9000/?proxy=127.0.0.1", "", "", false},
		{"kubernetes://cluster.example/?", "", "", false},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseServiceSelector(test.input)
			if err != nil || !got.Resource || got.EscapedPath != test.path || got.RawQuery != test.query || got.ForceQuery != test.forceQuery {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
}

func TestServiceSelectorRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		" ", " api", "api\n", "api/path", "api.example/path", "api.example?key", "abc_123", "svc_short",
		"svc_0123456789abcdefghijkl.example", "srun_0123456789abcdefghijkl", "api..example", "*.example",
		":443", "api:", "api:0", "api:65536", "api:+443", "api:-1", "api: 443", "api:443/path",
		"[127.0.0.1]:443", "[api.example]:443", "[::1]:", "[::1]extra", "[::1:443", "[fe80::1%en0]:443",
		"https://", "https:/api.example", "https://:443", "https://api.example:", "https://api.example:0",
		"https://api.example:+443", "https://api.example:65536", "https://2001:db8::1", "https://[api.example]",
		"https://[fe80::1%25en0]/", "https://api.example/%ZZ", "https://api.example/#", "https://api.example#anchor",
		"https://login:private-input@api.example", "https://login:private-input@api.example/%ZZ",
		"https://@api.example", "postgres://login:private-input@db.example", "tcp://api.example", "redis://db.example",
	} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseServiceSelector(input)
			if err == nil || (got != ServiceSelector{}) {
				t.Fatalf("got %#v, %v; want an error and no selector", got, err)
			}
			if strings.Contains(err.Error(), "private-input") {
				t.Fatalf("error included credentials: %v", err)
			}
		})
	}
}

func TestServiceSelectorMatchesEndpoint(t *testing.T) {
	for _, test := range []struct {
		input, protocol, host string
		port                  int
		want                  bool
	}{
		{"", "http", "api.example", 443, false},
		{"api", "http", "api", 443, false},
		{"svc_0123456789ABCDefghijkl", "http", "api.example", 443, false},
		{"api.example", "tcp", "API.EXAMPLE.", 9000, true},
		{"api.example", "tcp", "api.example.other", 9000, false},
		{"api.example:9000", "postgres", "api.example", 9000, true},
		{"api.example:9000", "tcp", "api.example", 443, false},
		{"api.example:9000", "tcp", "api.example", 0, false},
		{"api.example:9000", "tcp", "other.example", 9000, false},
		{"https://api.example", "http", "api.example", 443, true},
		{"https://api.example", "http", "api.example", 80, false},
		{"https://api.example", "kubernetes", "api.example", 443, false},
		{"https://api.example:8443", "http", "api.example", 8443, true},
		{"https://api.example/health", "http", "api.example", 443, true},
		{"postgresql://db.example", "postgres", "db.example", 5432, true},
		{"postgresql://db.example", "tcp", "db.example", 5432, false},
		{"postgresql://db.example", "postgres", "db.example", 15432, false},
		{"tcp://api.example:9000", "postgres", "api.example", 9000, false},
		{"[2001:db8::1]:443", "http", "2001:0db8::1", 443, true},
	} {
		s, err := ParseServiceSelector(test.input)
		if err != nil {
			t.Fatalf("ParseServiceSelector(%q): %v", test.input, err)
		}
		if got := s.MatchesEndpoint(test.protocol, test.host, test.port); got != test.want {
			t.Errorf("%q matches (%s, %s, %d) = %t; want %t", test.input, test.protocol, test.host, test.port, got, test.want)
		}
	}
}
