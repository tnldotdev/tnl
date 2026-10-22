package target

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestNormalizeTarget(t *testing.T) {
	accepted := map[string]string{
		"3000":                           "http://127.0.0.1:3000",
		"03000":                          "http://127.0.0.1:3000",
		"localhost:3000":                 "http://127.0.0.1:3000",
		"LOCALHOST:03000":                "http://127.0.0.1:3000",
		"http://localhost:3000":          "http://127.0.0.1:3000",
		"HTTP://LOCALHOST:03000":         "http://127.0.0.1:3000",
		"http://127.0.0.1:3000":          "http://127.0.0.1:3000",
		"http://127.0.0.2:03000":         "http://127.0.0.2:3000",
		"http://[::1]:3000":              "http://[::1]:3000",
		"http://[0:0:0:0:0:0:0:1]:03000": "http://[::1]:3000",
		"HTTP://[0:0:0:0:0:0:0:1]:3000":  "http://[::1]:3000",
		"http://app:3000":                "http://app:3000",
		"HTTP://WEB-API:03000":           "http://web-api:3000",
		"http://192.0.2.1:3000":          "http://192.0.2.1:3000",
		"http://[::2]:3000":              "http://[::2]:3000",
		"https://localhost:3000":         "https://localhost:3000",
		"HTTPS://API.EXAMPLE:0443":       "https://api.example:443",
		"https://127.0.0.1:3000":         "https://127.0.0.1:3000",
		"https://api.openai.com":         "https://api.openai.com:443",
		"http://127.0.0.1":               "http://127.0.0.1:80",
		"https://app":                    "https://app:443",
	}
	for target, want := range accepted {
		t.Run(target, func(t *testing.T) {
			got, err := NormalizeTarget(target)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("NormalizeTarget(%q) = %q, want %q", target, got, want)
			}
		})
	}
	for _, target := range []string{
		"", "0", "65536", "+3000", "-3000", "30x00", "127.0.0.1:3000",
		" 3000", "3000 ", "3 000", "\t3000",
		"localhost", "localhost:", "localhost:3000/path", "localhost:3000:4000",
		"http://localhost.:3000", "http://-app:3000", "http://app_:3000", "http://[fe80::1%25en0]:3000",
		"http://127.0.0.1:0", "ftp://app:3000", "http://127.0.0.1:65536", "http://127.0.0.1:bad",
		"http://127.0.0.1:3000/", "http://127.0.0.1:3000/path", "http://user@127.0.0.1:3000", "http://127.0.0.1:3000?query",
		"http://127.0.0.1:3000#fragment", "https://user@app:3000", "https://app:3000/",
	} {
		t.Run(target, func(t *testing.T) {
			if got, err := NormalizeTarget(target); err == nil {
				t.Fatalf("NormalizeTarget(%q) = %q, want error", target, got)
			} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetInvalid {
				t.Fatalf("NormalizeTarget(%q) diagnostic = %q, %t", target, code, ok)
			}
		})
	}
}

func TestParseCanonicalTarget(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:3000", "https://[::1]:443", "http://192.0.2.1:3000"} {
		parsed, err := ParseCanonicalTarget(target)
		if err != nil || parsed.String() != target {
			t.Fatalf("canonical target %q = %v, %v", target, parsed, err)
		}
	}
	for _, target := range []string{"3000", "http://localhost:3000", "HTTP://127.0.0.1:03000", "http://127.0.0.1:3000/path"} {
		if _, err := ParseCanonicalTarget(target); err == nil {
			t.Fatalf("noncanonical target %q was accepted", target)
		}
	}
}

func FuzzNormalizeTarget(f *testing.F) {
	for _, target := range []string{"3000", "03000", "http://127.0.0.1:3000", "HTTP://[0:0:0:0:0:0:0:1]:03000", "localhost:3000", "http://localhost:3000", "http://127.0.0.1:3000/path", "http://user@127.0.0.1:3000", "http://127.0.0.1:3000#fragment", "https://api.example:443", "http://app:3000"} {
		f.Add(target)
	}
	f.Fuzz(func(t *testing.T, target string) {
		canonical, err := NormalizeTarget(target)
		if err != nil {
			return
		}
		roundTrip, err := NormalizeTarget(canonical)
		if err != nil || roundTrip != canonical {
			t.Fatalf("canonical target is not idempotent: %q, %v", roundTrip, err)
		}
		parsed, err := url.Parse(canonical)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" {
			t.Fatalf("unsafe canonical target %q: %#v, %v", canonical, parsed, err)
		}
		host := parsed.Hostname()
		if address, err := netip.ParseAddr(host); err == nil {
			if address.Zone() != "" || address.String() != host {
				t.Fatalf("canonical target has invalid IP address: %q", canonical)
			}
		} else if normalized, err := naming.CanonicalizeHostname(host); err != nil || normalized != host {
			t.Fatalf("canonical target has invalid DNS name: %q", canonical)
		}
		port, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || port == 0 {
			t.Fatalf("canonical target has invalid port: %q", canonical)
		}
		want := parsed.Scheme + "://" + net.JoinHostPort(host, strconv.FormatUint(port, 10))
		if canonical != want {
			t.Fatalf("canonical target = %q, want %q", canonical, want)
		}
	})
}
