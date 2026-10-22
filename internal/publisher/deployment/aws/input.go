// package awsbootstrap prepares publisher identity secrets and nonsecret bindings.
// its provider interface cannot deploy compute, networking, or storage resources.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// DeploymentFile is customer-owned, separate from generated artifacts and tnl
// service configuration. parameters may include network resources created later.
type DeploymentFile struct {
	SchemaVersion int          `json:"schema_version"`
	Deployments   []Deployment `json:"deployments"`
}

type Deployment struct {
	Name           string            `json:"name"`
	PublisherGroup string            `json:"publisher_group"`
	AccountID      string            `json:"account_id"`
	Region         string            `json:"region"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	Secrets        map[string]Secret `json:"identity_secrets,omitempty"`
}

type Secret struct {
	Name                string `json:"name,omitempty"`
	ExistingARN         string `json:"existing_arn,omitempty"`
	ExistingVersion     string `json:"existing_version,omitempty"`
	PublisherIdentityID string `json:"publisher_identity_id,omitempty"`
	KMSKeyID            string `json:"kms_key_id,omitempty"`
}

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+){1,2}-[0-9]$`)
var secretPattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
var parameterPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,254}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9-]{32,64}$`)

func invalid() error {
	return failure.Wrap("validate publisher deployment", failure.AWSBootstrapInvalid, errScope)
}

func ReadDeployment(path, publisher, name string) (Deployment, error) {
	f, err := os.Open(path)
	if err != nil {
		return Deployment{}, failure.Wrap("read customer deployment", failure.AWSBootstrapInvalid, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return Deployment{}, invalid()
	}
	data, err := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return Deployment{}, invalid()
	}
	var file DeploymentFile
	if json.Unmarshal(data, &file, json.RejectUnknownMembers(true)) != nil || file.SchemaVersion != 1 || len(file.Deployments) == 0 || len(file.Deployments) > 32 {
		return Deployment{}, invalid()
	}
	var selected *Deployment
	names := map[string]bool{}
	for _, d := range file.Deployments {
		if err := d.Validate(); err != nil || names[d.Name] {
			return Deployment{}, invalid()
		}
		names[d.Name] = true
		if d.PublisherGroup == publisher && (name == "" || d.Name == name) {
			if selected != nil {
				return Deployment{}, invalid()
			}
			selected = &d
		}
	}
	if selected == nil {
		return Deployment{}, invalid()
	}
	return *selected, nil
}

func (d Deployment) Validate() error {
	if !naming.ValidServiceName(d.Name) || !naming.ValidServiceName(d.PublisherGroup) || d.PublisherGroup == "local" || !accountPattern.MatchString(d.AccountID) || !regionPattern.MatchString(d.Region) || len(d.Parameters) > 128 || len(d.Secrets) > 32 {
		return invalid()
	}
	for k, v := range d.Parameters {
		if !parameterPattern.MatchString(k) || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return invalid()
		}
	}
	for slot, s := range d.Secrets {
		if !naming.ValidServiceName(slot) || s.Name != "" && !secretPattern.MatchString(s.Name) || s.Name != "" && s.ExistingARN != "" || len(s.KMSKeyID) > 2048 || strings.ContainsAny(s.KMSKeyID, "\x00\r\n") {
			return invalid()
		}
		if s.ExistingARN != "" && (!secretARN(s.ExistingARN, d.AccountID, d.Region) || s.KMSKeyID != "") {
			return invalid()
		}
		// keep customer names within the generated secret ARN parameter's bound,
		// including the longest supported partition and AWS's random suffix.
		if s.Name != "" && len("arn:aws-us-gov:secretsmanager:"+d.Region+":"+d.AccountID+":secret:"+s.Name+"-ABCDEF") > 512 {
			return invalid()
		}
		if (s.ExistingVersion != "") != (s.PublisherIdentityID != "") || s.ExistingVersion != "" && (s.ExistingARN == "" || !versionPattern.MatchString(s.ExistingVersion) || !opaqueid.Valid(s.PublisherIdentityID, opaqueid.PublisherIdentityPrefix)) {
			return invalid()
		}
	}
	return nil
}

func secretARN(value, account, region string) bool {
	a, err := arn.Parse(value)
	return err == nil && (a.Partition == "aws" || a.Partition == "aws-us-gov" || a.Partition == "aws-cn") && a.Service == "secretsmanager" && a.AccountID == account && a.Region == region && strings.HasPrefix(a.Resource, "secret:") && len(a.Resource) > 13 && len(value) <= 512
}

// Binding uses immutable group identity, never the mutable configuration name or
// an operator installation hash. source fingerprints identify the source path.
type Binding struct {
	ControlOrigin     string `json:"control_origin"`
	TeamID            string `json:"team_id"`
	ProjectKey        string `json:"project_key"`
	GroupID           string `json:"group_id"`
	SourceFingerprint string `json:"source_fingerprint"`
	AccountID         string `json:"account_id"`
	Region            string `json:"region"`
	DeploymentName    string `json:"deployment_name"`
	ReplicaSlot       string `json:"replica_slot"`
}

func (b Binding) ID() string {
	data, _ := json.Marshal(b)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func (b Binding) Instance() string { return "aws-" + b.ID()[:28] }

func (b Binding) validate() error {
	canonical, err := naming.CanonicalControlURL(b.ControlOrigin)
	hash, hashErr := hex.DecodeString(b.SourceFingerprint)
	if err != nil || canonical != b.ControlOrigin || b.TeamID == "" || len(b.TeamID) > 256 || !naming.ValidProjectKey(b.ProjectKey) || b.GroupID == "" || len(b.GroupID) > 256 || hashErr != nil || len(hash) != 32 || !accountPattern.MatchString(b.AccountID) || !regionPattern.MatchString(b.Region) || !naming.ValidServiceName(b.DeploymentName) || !naming.ValidServiceName(b.ReplicaSlot) {
		return invalid()
	}
	return nil
}

var errScope = errors.New("publisher deployment binding differs")
