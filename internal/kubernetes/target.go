package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/tnldotdev/tnl/internal/privatetrust"
)

var ErrCluster = errors.New("kubernetes cluster discovery returned an invalid HTTPS endpoint or cluster CA")

// DiscoveredCluster is publisher-owned discovery input, never client kubeconfig
// trust. the client verifies the independent managed tnl WebPKI hostname.
type DiscoveredCluster struct {
	Endpoint                 string
	CertificateAuthorityData string
}

type EKSDiscovery interface {
	DescribeEKS(context.Context, string, string) (DiscoveredCluster, error)
}

type Target struct {
	Address string
	TLS     *tls.Config
	CAPEM   []byte
	Trust   privatetrust.Snapshot
}

// ResolveEKS is the adapter for the publisher discovery owner. authentication
// remains the visiting client's bearer token, not a publisher IAM/PAM identity.
func ResolveEKS(ctx context.Context, discovery EKSDiscovery, region, cluster string) (Target, error) {
	if discovery == nil {
		return Target{}, ErrCluster
	}
	found, err := discovery.DescribeEKS(ctx, region, cluster)
	if err != nil {
		return Target{}, err
	}
	return VerifyTarget(found)
}

func VerifyTarget(found DiscoveredCluster) (Target, error) {
	u, err := url.Parse(found.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return Target{}, ErrCluster
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Target{}, ErrCluster
	}
	data, err := base64.StdEncoding.Strict().DecodeString(found.CertificateAuthorityData)
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return Target{}, ErrCluster
	}
	trust, err := privatetrust.CapturePEM(u.Hostname(), data)
	if err != nil {
		return Target{}, ErrCluster
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust.PEM) {
		return Target{}, ErrCluster
	}
	return Target{Address: net.JoinHostPort(trust.Hostname, port), TLS: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: trust.Hostname, RootCAs: roots}, CAPEM: trust.PEM, Trust: trust}, nil
}
