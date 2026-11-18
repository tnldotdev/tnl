package naming

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

type HostnameKind string

const (
	ServiceHostnameKind    HostnameKind = "s"
	ServiceRunHostnameKind HostnameKind = "r"
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

// RandomHostname gives generated service and exact-run addresses the same
// 128-bit label format. kind identifies what the address selects, not its
// lifetime or visitor policy. callers reserve and persist the resulting name.
func RandomHostname(kind HostnameKind, parent string) (string, error) {
	if !ValidGeneratedHostnameParent(parent) || kind != ServiceHostnameKind && kind != ServiceRunHostnameKind {
		return "", ErrGeneratedHostname
	}
	label, err := RandomHostnameLabel()
	if err != nil {
		return "", err
	}
	return string(kind) + "-" + label + "." + parent, nil
}
