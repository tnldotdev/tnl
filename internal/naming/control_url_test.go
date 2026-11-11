package naming

import (
	"errors"
	"testing"
)

func TestControlOriginTransport(t *testing.T) {
	for input, expected := range map[string]string{
		"https://CONTROL.example:443/": "https://control.example",
		"http://localhost:8445/":       "http://localhost:8445",
		"http://LOCALHOST:80/":         "http://localhost",
		"http://127.0.0.1:8445":        "http://127.0.0.1:8445",
		"http://[::1]:8445":            "http://[::1]:8445",
	} {
		actual, err := CanonicalControlURL(input)
		if err != nil || actual != expected {
			t.Fatalf("%q = %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, input := range []string{"http://control.example", "http://localhost.example", "http://localhost.", "http://192.168.1.1", "http://0.0.0.0", "http://[::]", "http://127.0.0.1.example", "http://user@localhost", "http://localhost/path", "http://localhost?query", "http://localhost#fragment"} {
		if _, err := CanonicalControlURL(input); !errors.Is(err, ErrInvalidControlURL) {
			t.Fatalf("%q: %v", input, err)
		}
	}
}
