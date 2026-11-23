package naming

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

type HostnameKind string

const (
	ServiceHostnameKind   HostnameKind = "s"
	PublisherHostnameKind HostnameKind = "p"
	// two bytes for the kind prefix, 26 for the label, and one separator.
	MaxGeneratedHostnameParentBytes = MaxHostnameBytes - 29
)

var ErrGeneratedHostname = errors.New("generated hostname kind or parent is invalid")

// RandomHostnameLabel encodes 128 random bits as 26 lowercase base32 characters.
// lifetime and visitor policy belong to the saved record, not this label.
func RandomHostnameLabel() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])), nil
}

func ValidGeneratedHostnameParent(parent string) bool {
	canonical, err := CanonicalizeHostname(parent)
	return err == nil && canonical == parent && len(parent) <= MaxGeneratedHostnameParentBytes
}

// RandomHostname gives generated service and publisher addresses the same
// 128-bit label format. kind identifies what the address selects, not its
// lifetime or visitor policy. callers reserve and persist the resulting name.
func RandomHostname(kind HostnameKind, parent string) (string, error) {
	if !ValidGeneratedHostnameParent(parent) || kind != ServiceHostnameKind && kind != PublisherHostnameKind {
		return "", ErrGeneratedHostname
	}
	label, err := RandomHostnameLabel()
	if err != nil {
		return "", err
	}
	return string(kind) + "-" + label + "." + parent, nil
}

func PreviewParent(parent, managedDomain string) bool {
	label, ok := strings.CutSuffix(parent, ".preview."+managedDomain)
	return ok && validRandomHostnameLabel(label)
}

func PreviewHostname(hostname, managedDomain string) (string, bool) {
	label, parent, _ := strings.Cut(hostname, ".")
	id, ok := strings.CutPrefix(label, "s-")
	return parent, ok && validRandomHostnameLabel(id) && PreviewParent(parent, managedDomain)
}

func validRandomHostnameLabel(label string) bool {
	if len(label) != 26 {
		return false
	}
	for _, ch := range label {
		if (ch < 'a' || ch > 'z') && (ch < '2' || ch > '7') {
			return false
		}
	}
	return true
}
