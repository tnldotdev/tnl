// package publisherprovenance validates publisher-reported deployment metadata.
// the control OpenAPI contract owns the wire fields; this package owns their
// environment adapter and deterministic digest for signed runtime assertions.
package publisherprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	DeploymentIDEnv    = "TNL_DEPLOYMENT_ID"
	ProviderEnv        = "TNL_DEPLOYMENT_PROVIDER"
	ReplicaKeyEnv      = "TNL_DEPLOYMENT_REPLICA_KEY"
	ImageEnv           = "TNL_DEPLOYMENT_IMAGE"
	TemplateVersionEnv = "TNL_DEPLOYMENT_TEMPLATE_VERSION"
	TemplateSHA256Env  = "TNL_DEPLOYMENT_TEMPLATE_SHA256"
)

var ErrInvalid = errors.New("publisher deployment metadata is invalid")
var deploymentID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
var image = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Validate(r *controlv1.PublisherDeploymentReport) error {
	if r == nil {
		return nil
	}
	if !deploymentID.MatchString(r.DeploymentId) || r.Provider != "aws" || !naming.ValidServiceName(r.ReplicaKey) || !naming.ValidServiceName(r.Instance) || len(r.Image) > 512 || !image.MatchString(r.Image) || !version.MatchString(r.SoftwareVersion) || len(r.TemplateVersion) > 32 || !version.MatchString(r.TemplateVersion) || !hash.MatchString(r.TemplateSha256) {
		return ErrInvalid
	}
	return nil
}

// Digest binds presence and every field without depending on generated struct
// field ordering. the versioned array is the canonical assertion input.
func Digest(r *controlv1.PublisherDeploymentReport) string {
	if r == nil {
		return ""
	}
	data, _ := json.Marshal([]string{"tnl publisher deployment v1", r.DeploymentId, string(r.Provider), r.ReplicaKey, r.Instance, r.Image, r.SoftwareVersion, r.TemplateVersion, r.TemplateSha256})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func SameBinding(a, b *controlv1.PublisherDeploymentReport) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.DeploymentId == b.DeploymentId && a.Provider == b.Provider && a.ReplicaKey == b.ReplicaKey && a.Instance == b.Instance
}

// ReadEnvironment is read-only. no keys, tenant selectors, timestamps or exporter
// configuration are accepted here. callers supply the verified instance and the
// binary's build version; partial or explicitly empty metadata fails closed.
func ReadEnvironment(lookup func(string) (string, bool), instance, softwareVersion string) (*controlv1.PublisherDeploymentReport, error) {
	var r controlv1.PublisherDeploymentReport
	provider := ""
	fields := []struct {
		name  string
		value *string
	}{{DeploymentIDEnv, &r.DeploymentId}, {ProviderEnv, &provider}, {ReplicaKeyEnv, &r.ReplicaKey}, {ImageEnv, &r.Image}, {TemplateVersionEnv, &r.TemplateVersion}, {TemplateSHA256Env, &r.TemplateSha256}}
	present := false
	for _, field := range fields {
		value, found := lookup(field.name)
		present = present || found
		*field.value = value
	}
	if !present {
		return nil, nil
	}
	r.Provider = controlv1.PublisherDeploymentReportProvider(provider)
	r.Instance, r.SoftwareVersion = instance, softwareVersion
	if err := Validate(&r); err != nil {
		return nil, failure.Wrap("read publisher deployment metadata", failure.PublisherDeploymentMetadataInvalid, err)
	}
	return &r, nil
}
