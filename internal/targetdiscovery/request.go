// package targetdiscovery resolves cloud targets in the publisher's credential
// and network boundary. discovery never retrieves application credentials.
package targetdiscovery

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

// Request is independent of control's wire descriptor. Account, when supplied,
// must match both the credential account and the returned resource ARN.
type Request struct {
	Type, Region, Cluster, Instance, Endpoint, Protocol string
	Account                                             string
}

var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
var eksName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
var rdsName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var resourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_:/.-]{0,255}$`)

func (r Request) Normalize() (Request, error) {
	if len(r.Region) > 32 || !regionPattern.MatchString(r.Region) || r.Account != "" && !accountPattern.MatchString(r.Account) {
		return Request{}, discoveryError(Invalid, nil)
	}
	switch r.Type {
	case "eks":
		if !eksName.MatchString(r.Cluster) || r.Instance != "" || r.Endpoint != "" || r.Protocol != "kubernetes" {
			return Request{}, discoveryError(Invalid, nil)
		}
	case "rds":
		if (r.Cluster == "") == (r.Instance == "") || r.Protocol != "postgres" && r.Protocol != "mysql" {
			return Request{}, discoveryError(Invalid, nil)
		}
		name := r.Cluster
		if r.Instance != "" {
			name = r.Instance
		}
		if !rdsName.MatchString(name) || strings.HasSuffix(name, "-") || strings.Contains(name, "--") {
			return Request{}, discoveryError(Invalid, nil)
		}
		if r.Endpoint == "" {
			r.Endpoint = "writer"
		}
		if r.Endpoint != "writer" && r.Endpoint != "reader" || r.Endpoint == "reader" && r.Instance != "" {
			return Request{}, discoveryError(Invalid, nil)
		}
	default:
		return Request{}, discoveryError(Invalid, nil)
	}
	return r, nil
}

// FromServiceTarget is the source-config adapter; it performs no AWS I/O.
func FromServiceTarget(target config.ServiceTarget, protocol config.ProtocolName) (Request, error) {
	if target.Address != nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil || target.TLS != nil {
		return Request{}, discoveryError(Invalid, nil)
	}
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return (Request{Type: target.Type, Region: value(target.Region), Cluster: value(target.Cluster), Instance: value(target.Instance), Endpoint: value(target.Endpoint), Protocol: string(protocol)}).Normalize()
}

// ResolvedTarget is immutable bounded metadata, not a DNS answer or connection.
// CA contains only public certificates. formatting never prints provider data.
type ResolvedTarget struct {
	Address, ServerName, CA, CADigest string
	ARN, ResourceID, CAIdentifier     string
	Protocol                          string
	generation                        uint64
}

func (ResolvedTarget) String() string   { return "resolved cloud target" }
func (ResolvedTarget) GoString() string { return "resolved cloud target" }

func (t ResolvedTarget) Verifier() (*tls.Config, error) {
	if !validHostname(t.ServerName) || len(t.CA) == 0 || len(t.CA) > 64<<10 || digest(t.CA) != t.CADigest {
		return nil, discoveryError(Metadata, nil)
	}
	pool := x509.NewCertPool()
	rest := []byte(t.CA)
	count := 0
	for len(strings.TrimSpace(string(rest))) != 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(rest)), "-----BEGIN CERTIFICATE-----") {
			return nil, discoveryError(Metadata, nil)
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, discoveryError(Metadata, nil)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, discoveryError(Metadata, err)
		}
		pool.AddCert(cert)
		rest = next
		count++
		if count > 16 {
			return nil, discoveryError(Metadata, nil)
		}
	}
	if count == 0 {
		return nil, discoveryError(Metadata, nil)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.ServerName, RootCAs: pool}, nil
}

func digest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil || strings.ToLower(host) != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return strings.Contains(host, ".")
}

// Kind is a closed diagnostic classification. Error retains causes for typed
// inspection, but neither Error nor GoString includes raw SDK response text.
type Kind string

const (
	Invalid        Kind = "invalid"
	Permission     Kind = "permission"
	Authentication Kind = "authentication"
	NotFound       Kind = "not_found"
	Unavailable    Kind = "unavailable"
	NotReady       Kind = "not_ready"
	Metadata       Kind = "metadata"
	Changed        Kind = "changed"
	Stale          Kind = "stale"
)

type Error struct {
	Kind  Kind
	cause error
}

func (e *Error) Error() string {
	switch e.Kind {
	case Invalid:
		return "cloud target selector or protocol is invalid; check the target declaration"
	case Permission:
		return "cloud target discovery was denied; allow the selected resource's Describe action on the publisher role"
	case Authentication:
		return "cloud target credentials are unavailable or rejected; check the publisher's AWS credential chain"
	case NotFound:
		return "cloud target was not found; check the declared region and resource identifier"
	case NotReady:
		return "cloud target is not ready; wait for the selected resource to become available"
	case Metadata:
		return "cloud target metadata or TLS trust is invalid; check the selected resource"
	case Changed:
		return "cloud target resource or CA changed; prepare a new publication"
	case Stale:
		return "cloud target discovery is stale; restore publisher access to AWS before opening new connections"
	default:
		return "cloud target discovery is unavailable; retry when AWS is reachable"
	}
}
func (e *Error) GoString() string { return e.Error() }
func (e *Error) Unwrap() error    { return e.cause }
func (e *Error) FailureReason() failure.Reason {
	switch e.Kind {
	case Invalid:
		return failure.TargetDiscoveryInvalid
	case Permission:
		return failure.TargetDiscoveryDenied
	case Authentication:
		return failure.TargetDiscoveryAuthentication
	case NotFound:
		return failure.TargetDiscoveryNotFound
	case NotReady:
		return failure.TargetDiscoveryNotReady
	case Metadata:
		return failure.TargetDiscoveryMetadata
	case Changed:
		return failure.TargetDiscoveryChanged
	case Stale:
		return failure.TargetDiscoveryStale
	default:
		return failure.TargetDiscoveryUnavailable
	}
}

func (t ResolvedTarget) validate(request Request) error {
	host, port, err := net.SplitHostPort(t.Address)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 1 || n > 65535 || host != t.ServerName || len(t.Address) > 260 || t.Protocol != request.Protocol || len(t.ARN) == 0 || len(t.ARN) > 512 || !resourcePattern.MatchString(t.ResourceID) || len(t.CAIdentifier) > 128 {
		return discoveryError(Metadata, nil)
	}
	_, err = t.Verifier()
	return err
}
func discoveryError(kind Kind, cause error) error { return &Error{Kind: kind, cause: cause} }
func ErrorKind(err error) Kind {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Unavailable
}
