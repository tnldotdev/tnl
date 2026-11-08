package workloadsetup

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrKubernetesAuthentication = errors.New("workload setup needs an authenticated kubectl context with service-account and issuer-discovery read access")

func (r resolver) kubernetes(ctx context.Context, o Options, k *config.WorkloadKubernetes, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, *controlv1.ProjectWorkloadKubernetes, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadKubernetes, Audience: o.Server, Claims: map[string]string{}}
	if k.Audience != "" {
		t.Audience = k.Audience
	}
	prefix := []string{}
	if k.Context != "" {
		prefix = append(prefix, "--context", k.Context)
	}
	run := func(args ...string) ([]byte, error) {
		output, err := r.run(ctx, o.Directory, "kubectl", append(append([]string{}, prefix...), args...)...)
		if err != nil {
			return nil, errors.Join(ErrKubernetesAuthentication, err)
		}
		return output, nil
	}
	output, err := run("config", "view", "--minify", "--output=json")
	if err != nil {
		return t, nil, err
	}
	var selected struct {
		Contexts []struct {
			Name    string `json:"name"`
			Context struct {
				Namespace string `json:"namespace"`
				Cluster   string `json:"cluster"`
			} `json:"context"`
		} `json:"contexts"`
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server   string `json:"server"`
				Insecure bool   `json:"insecure-skip-tls-verify"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if json.Unmarshal(output, &selected) != nil || len(selected.Contexts) != 1 || len(selected.Clusters) != 1 {
		return t, nil, ErrBinding
	}
	c, cluster := selected.Contexts[0], selected.Clusters[0]
	if !config.ExactWorkloadValue(c.Name) || k.Context != "" && c.Name != k.Context || c.Context.Cluster != cluster.Name || cluster.Cluster.Insecure || !config.WorkloadHTTPS(cluster.Cluster.Server) {
		return t, nil, ErrBinding
	}
	namespace := k.Namespace
	if namespace == "" {
		namespace = c.Context.Namespace
	}
	if namespace == "" {
		namespace = "default"
	}
	if !naming.ValidAuthorityLabel(namespace) {
		return t, nil, ErrBinding
	}
	prefix = []string{"--context", c.Name}
	selectors := &controlv1.ProjectWorkloadKubernetes{Context: c.Name, ClusterServer: cluster.Cluster.Server, Namespace: namespace, ServiceAccount: k.ServiceAccount}
	subject := "system:serviceaccount:" + namespace + ":" + k.ServiceAccount
	old := previous.Trust
	if previous.Provider == t.Provider && previous.Kubernetes != nil && *previous.Kubernetes == *selectors && old.Claims["sub"] == subject && config.ValidKubernetesUID(old.Claims["service_account_uid"]) {
		t.Issuer, t.JwksUrl, t.Claims = old.Issuer, old.JwksUrl, cloneClaims(old.Claims)
		return t, selectors, nil
	}
	output, err = run("--namespace", namespace, "get", "serviceaccount", k.ServiceAccount, "--output=json")
	if err != nil {
		return t, nil, err
	}
	var account struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(output, &account) != nil || account.Metadata.Name != k.ServiceAccount || account.Metadata.Namespace != namespace || !config.ValidKubernetesUID(account.Metadata.UID) {
		return t, nil, ErrBinding
	}
	output, err = run("get", "--raw", "/.well-known/openid-configuration")
	if err != nil {
		return t, nil, err
	}
	var discovery struct {
		Issuer string `json:"issuer"`
		Keys   string `json:"jwks_uri"`
	}
	if json.Unmarshal(output, &discovery) != nil || !config.WorkloadHTTPS(discovery.Issuer) || !config.WorkloadHTTPS(discovery.Keys) {
		return t, nil, ErrBinding
	}
	if previous.Provider == t.Provider && (old.Issuer != discovery.Issuer || old.JwksUrl != discovery.Keys || old.Claims["sub"] != subject || old.Claims["service_account_uid"] != account.Metadata.UID) {
		return t, nil, ErrRebinding
	}
	t.Issuer, t.JwksUrl = discovery.Issuer, discovery.Keys
	t.Claims = map[string]string{"sub": subject, "service_account_uid": account.Metadata.UID}
	return t, selectors, nil
}
