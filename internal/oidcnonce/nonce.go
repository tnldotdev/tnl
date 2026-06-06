package oidcnonce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strings"
)

const prefix = "tnl-core-v1"

func New(coreEndpoint string) (string, error) {
	if err := ValidateCoreEndpoint(coreEndpoint); err != nil {
		return "", err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	digest := endpointDigest(coreEndpoint)
	return prefix + "." + base64.RawURLEncoding.EncodeToString(digest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(random[:]), nil
}

func ValidateCoreEndpoint(coreEndpoint string) error {
	if !canonicalEndpoint(coreEndpoint) {
		return errors.New("oidcnonce: Core endpoint must be canonical")
	}
	return nil
}

func Validate(coreEndpoint, nonce string) bool {
	if !canonicalEndpoint(coreEndpoint) {
		return false
	}
	parts := strings.Split(nonce, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return false
	}
	want := endpointDigest(coreEndpoint)
	got, err := decode32(parts[1])
	if err != nil || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return false
	}
	_, err = decode32(parts[2])
	return err == nil
}

func endpointDigest(coreEndpoint string) [32]byte {
	return sha256.Sum256([]byte("tnl-core-oidc-v1\x00" + coreEndpoint))
}

func decode32(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(result) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return result, errors.New("oidcnonce: invalid component")
	}
	copy(result[:], decoded)
	return result, nil
}

func canonicalEndpoint(value string) bool {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return false
	}
	hostname := strings.ToLower(origin.Hostname())
	if hostname == "" {
		return false
	}
	port := origin.Port()
	if port == "" || port == "443" {
		if strings.Contains(hostname, ":") {
			origin.Host = "[" + hostname + "]"
		} else {
			origin.Host = hostname
		}
	} else {
		origin.Host = net.JoinHostPort(hostname, port)
	}
	return origin.String() == value
}
