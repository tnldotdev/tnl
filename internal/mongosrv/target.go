// package mongosrv validates a mongodb DNS seedlist used as a private target.
package mongosrv

import (
	"errors"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

const Prefix = "mongodb+srv://"

// Parse accepts only a seed hostname. visitor credentials and database options
// belong to the visiting client, not to the publisher's private target.
func Parse(target string) (string, error) {
	if !strings.HasPrefix(target, Prefix) {
		return "", errors.New("mongodb SRV target must use mongodb+srv://")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Port() != "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return "", errors.New("mongodb SRV target must contain only a seed hostname; configure credentials on the visiting client")
	}
	seed, err := naming.CanonicalizeHostname(parsed.Host)
	if err != nil || seed != parsed.Host || !strings.Contains(seed, ".") {
		return "", errors.New("mongodb SRV target needs a canonical seed hostname")
	}
	return seed, nil
}
