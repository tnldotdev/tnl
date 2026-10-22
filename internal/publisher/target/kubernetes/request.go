// package kubernetes owns native Kubernetes request semantics, not tunnel transport.
package kubernetes

import (
	"net/http"
	"strings"
)

// RequestClass contains bounded operation labels only. namespaces, object names,
// queries, payloads and exec arguments are never copied into observations.
type RequestClass struct {
	Verb, APIGroup, Resource, Subresource string
	LongRunning                           bool
}

func Classify(r *http.Request) RequestClass {
	c := RequestClass{Verb: "other", APIGroup: "other", Resource: "other", Subresource: "none"}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || len(r.URL.Path) > 4096 || r.URL.RawPath != "" {
		return c
	}
	switch parts[0] {
	case "api":
		c.APIGroup, parts = "core", parts[2:]
	case "apis":
		if len(parts) < 3 {
			return c
		}
		switch parts[1] {
		case "apps", "batch", "autoscaling", "policy", "rbac.authorization.k8s.io", "networking.k8s.io", "storage.k8s.io", "apiextensions.k8s.io", "discovery.k8s.io", "coordination.k8s.io", "metrics.k8s.io":
			c.APIGroup = parts[1]
		}
		parts = parts[3:]
	default:
		return c
	}
	if len(parts) >= 3 && parts[0] == "namespaces" {
		parts = parts[2:]
	}
	if len(parts) == 0 {
		c.Verb = "discovery"
		return c
	}
	switch parts[0] {
	case "pods", "services", "endpoints", "namespaces", "nodes", "configmaps", "secrets", "serviceaccounts", "persistentvolumes", "persistentvolumeclaims", "events", "deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "ingresses", "customresourcedefinitions", "leases":
		c.Resource = parts[0]
	}
	if len(parts) >= 3 {
		switch parts[2] {
		case "status", "scale", "log", "exec", "attach", "portforward":
			c.Subresource = parts[2]
		}
	}
	switch r.Method {
	case http.MethodGet:
		c.Verb = "get"
		if len(parts) == 1 {
			c.Verb = "list"
		}
		if r.URL.Query().Get("watch") == "true" || r.URL.Query().Get("watch") == "1" {
			c.Verb, c.LongRunning = "watch", true
		}
	case http.MethodPost:
		c.Verb = "create"
	case http.MethodPut:
		c.Verb = "update"
	case http.MethodPatch:
		c.Verb = "patch"
	case http.MethodDelete:
		c.Verb = "delete"
	}
	if c.Subresource == "exec" || c.Subresource == "attach" || c.Subresource == "portforward" || c.Subresource == "log" && r.URL.Query().Get("follow") == "true" {
		c.LongRunning = true
	}
	return c
}
