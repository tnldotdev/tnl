package connector

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"k8s.io/client-go/tools/clientcmd"
)

// localKubeconfig uses the caller's existing cluster credentials. it never
// creates a context or selects a different cluster after local discovery fails.
func localKubeconfig(server string, trust *connectorruntime.TLSOptions) (string, string, error) {
	if trust == nil {
		return "", "", errors.New("local Kubernetes requires target TLS")
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	configuration, err := rules.Load()
	if err != nil {
		return "", "", err
	}
	contextName := configuration.CurrentContext
	context := configuration.Contexts[contextName]
	if context == nil || contextName == "" {
		return "", "", errors.New("local Kubernetes requires a selected kubeconfig context")
	}
	cluster := configuration.Clusters[context.Cluster]
	if cluster == nil || cluster.InsecureSkipTLSVerify {
		return "", "", errors.New("local Kubernetes requires a verified kubeconfig cluster")
	}
	origin, err := url.Parse(cluster.Server)
	if err != nil || origin.Scheme != "https" || origin.User != nil || origin.Path != "" && origin.Path != "/" || origin.RawQuery != "" || origin.Fragment != "" {
		return "", "", errors.New("local Kubernetes kubeconfig server must match the loopback listener")
	}
	address := origin.Host
	if host, port, err := net.SplitHostPort(address); err == nil && host == "localhost" {
		address = net.JoinHostPort("127.0.0.1", port)
	}
	declared, parseErr := netip.ParseAddrPort(strings.TrimPrefix(server, "https://"))
	selected, selectedErr := netip.ParseAddrPort(address)
	if parseErr != nil || selectedErr != nil || declared != selected {
		return "", "", errors.New("local Kubernetes kubeconfig server must match the loopback listener")
	}
	tlsName := cluster.TLSServerName
	if tlsName == "" {
		tlsName = origin.Hostname()
	}
	if tlsName != trust.ServerName {
		return "", "", errors.New("local Kubernetes kubeconfig TLS identity must match target.tls")
	}
	caData := cluster.CertificateAuthorityData
	if cluster.CertificateAuthority != "" {
		if len(caData) != 0 {
			return "", "", errors.New("local Kubernetes kubeconfig CA must match target.tls")
		}
		caData, err = os.ReadFile(cluster.CertificateAuthority)
		if err != nil {
			return "", "", err
		}
	}
	if trust.CA != "" {
		if len(caData) == 0 {
			return "", "", errors.New("local Kubernetes kubeconfig CA must match target.tls")
		}
		ca, err := targettrust.CapturePEM(tlsName, caData)
		if err != nil || string(ca.PEM) != trust.CA {
			return "", "", errors.New("local Kubernetes kubeconfig CA must match target.tls")
		}
	} else if len(caData) != 0 {
		return "", "", errors.New("local Kubernetes kubeconfig CA must match target.tls")
	}
	paths := make([]string, 0, len(rules.Precedence))
	for _, path := range rules.Precedence {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", "", err
		}
		paths = append(paths, absolute)
	}
	if len(paths) == 0 {
		return "", "", errors.New("local Kubernetes requires a kubeconfig file")
	}
	return strings.Join(paths, string(os.PathListSeparator)), contextName, nil
}
