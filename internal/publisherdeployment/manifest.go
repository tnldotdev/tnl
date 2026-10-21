// package publisherdeployment owns offline publisher deployment artifacts and
// the nonsecret parameter contract consumed by identity bootstrap tooling.
package publisherdeployment

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/workloadmanifest"
)

const (
	SchemaVersion             = 1
	TemplateVersion           = "2"
	DefaultOutputDir          = ".tnl/generated"
	ManifestPath              = "manifest.json"
	DocumentationPath         = "readme.md"
	MaxManifestBytes          = 256 << 10
	MaxArtifactBytes          = 1 << 20
	ControlURLParameter       = "ControlURL"
	ProjectKeyParameter       = "ProjectKey"
	GroupParameter            = "Group"
	TeamIDParameter           = "TeamID"
	PublisherGroupIDParameter = "PublisherGroupID"
	DeploymentIDParameter     = "DeploymentID"
	TemplateSHA256Parameter   = "TemplateSHA256"
)

//go:embed instructions.md
var instructions []byte

type Manifest struct {
	SchemaVersion       int         `json:"schema_version"`
	ProjectKey          string      `json:"project_key"`
	SourceFingerprint   string      `json:"source_fingerprint"`
	DocumentationPath   string      `json:"documentation_path"`
	DocumentationSHA256 string      `json:"documentation_sha256"`
	Publishers          []Publisher `json:"publishers"`
	DeclarationsSHA256  string      `json:"declarations_sha256,omitempty"`
	WorkloadsSHA256     string      `json:"workloads_sha256,omitempty"`
}

type Publisher struct {
	Name                     string    `json:"name"`
	Provider                 string    `json:"provider"`
	ConfigurationFingerprint string    `json:"configuration_fingerprint"`
	TemplatePath             string    `json:"template_path"`
	TemplateSHA256           string    `json:"template_sha256"`
	ParametersExamplePath    string    `json:"parameters_example_path"`
	ParametersExampleSHA256  string    `json:"parameters_example_sha256"`
	Replicas                 []Replica `json:"replicas"`
}

type Replica struct {
	Key                            string `json:"key"`
	IdentitySecretARNParameter     string `json:"identity_secret_arn_parameter"`
	IdentitySecretVersionParameter string `json:"identity_secret_version_parameter"`
	InstanceParameter              string `json:"instance_parameter"`
	PublisherIdentityIDParameter   string `json:"publisher_identity_id_parameter"`
}

// Parameters contains references and public identifiers only, never secret JSON.
type Parameters map[string]string

// Parameter is the AWS CLI/SDK parameter-file representation.
type Parameter struct {
	ParameterKey   string `json:"ParameterKey"`
	ParameterValue string `json:"ParameterValue"`
}

func (p Parameters) CloudFormation() []Parameter {
	result := make([]Parameter, 0, len(p))
	for _, key := range slices.Sorted(maps.Keys(p)) {
		result = append(result, Parameter{key, p[key]})
	}
	return result
}

type Bundle struct {
	Manifest Manifest
	Files    map[string][]byte
}

func replica(index int) Replica {
	prefix := fmt.Sprintf("Replica%d", index)
	return Replica{Key: fmt.Sprintf("replica-%d", index), IdentitySecretARNParameter: prefix + "IdentitySecretArn", IdentitySecretVersionParameter: prefix + "IdentitySecretVersion", InstanceParameter: prefix + "Instance", PublisherIdentityIDParameter: prefix + "PublisherIdentityID"}
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func encode(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

// Generate uses declared capacity, cloud resource selectors, and stable source
// identity. discovered addresses, sessions, and checkout paths are not serialized.
func Generate(configuration config.TNL, source projectconfig.SourceIdentity, declarations ...[]byte) (Bundle, error) {
	result := Bundle{Manifest: Manifest{SchemaVersion: SchemaVersion, ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, Publishers: []Publisher{}}, Files: map[string][]byte{}}
	result.Manifest.DocumentationPath, result.Manifest.DocumentationSHA256 = DocumentationPath, digest(instructions)
	result.Files[DocumentationPath] = bytes.Clone(instructions)
	if err := config.ValidateTNL(configuration); err != nil {
		return result, err
	}
	if len(configuration.Workloads) > 0 {
		data, err := workloadmanifest.Generate(configuration, source)
		if err != nil {
			return result, err
		}
		result.Files[workloadmanifest.Filename] = data
		result.Manifest.WorkloadsSHA256 = digest(data)
	}
	for _, name := range slices.Sorted(maps.Keys(configuration.Publishers)) {
		aws := configuration.Publishers[name].AWS
		if aws == nil {
			continue
		}
		p := Publisher{Name: name, Provider: "aws", TemplatePath: "aws/" + name + ".yaml", ParametersExamplePath: "aws/" + name + ".parameters.example.json"}
		targets := map[string]*config.ServiceTarget{}
		for serviceName, service := range configuration.Services {
			if config.PublisherName(service) == name && (config.TargetType(service) == "eks" || config.TargetType(service) == "rds") {
				targets[serviceName] = service.Target
			}
		}
		capacity, err := encode(struct {
			Name     string                           `json:"name"`
			Replicas int                              `json:"replicas"`
			Targets  map[string]*config.ServiceTarget `json:"targets,omitempty"`
		}{name, aws.ReplicaCount(), targets})
		if err != nil {
			return result, err
		}
		p.ConfigurationFingerprint = digest(capacity)
		for i := 1; i <= aws.ReplicaCount(); i++ {
			p.Replicas = append(p.Replicas, replica(i))
		}
		template, example, err := RenderAWS(p, source.Key, configuration)
		if err != nil {
			return result, err
		}
		p.TemplateSHA256, p.ParametersExampleSHA256 = digest(template), digest(example)
		result.Files[p.TemplatePath], result.Files[p.ParametersExamplePath] = template, example
		result.Manifest.Publishers = append(result.Manifest.Publishers, p)
	}
	if len(declarations) != 0 {
		result.Files["project.d.ts"] = bytes.Clone(declarations[0])
		result.Manifest.DeclarationsSHA256 = digest(declarations[0])
	}
	if err := result.Manifest.Validate(); err != nil {
		return result, err
	}
	data, err := encode(result.Manifest)
	result.Files[ManifestPath] = data
	return result, err
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

// Validate bounds and validates the in-memory manifest, including canonical
// artifact paths and exact per-replica parameter names. Read also checks bytes.
func (m Manifest) Validate() error {
	if m.WorkloadsSHA256 != "" && !validHash(m.WorkloadsSHA256) {
		return errors.New("invalid workload manifest digest")
	}
	if m.SchemaVersion != SchemaVersion || (len(m.Publishers) != 0 || m.ProjectKey != "" || m.SourceFingerprint != "") && (!naming.ValidProjectKey(m.ProjectKey) || !validHash(m.SourceFingerprint)) || m.DocumentationPath != DocumentationPath || !validHash(m.DocumentationSHA256) || m.Publishers == nil || len(m.Publishers) > 32 || m.DeclarationsSHA256 != "" && !validHash(m.DeclarationsSHA256) {
		return errors.New("invalid publisher manifest version or source identity")
	}
	last := ""
	for _, p := range m.Publishers {
		if !naming.ValidServiceName(p.Name) || p.Name == "local" || p.Name <= last || p.Provider != "aws" || !validHash(p.ConfigurationFingerprint) || !validHash(p.TemplateSHA256) || !validHash(p.ParametersExampleSHA256) || p.TemplatePath != "aws/"+p.Name+".yaml" || p.ParametersExamplePath != "aws/"+p.Name+".parameters.example.json" || len(p.Replicas) < 1 || len(p.Replicas) > config.MaxPublisherReplicas {
			return errors.New("invalid publisher manifest entry")
		}
		last = p.Name
		for i, r := range p.Replicas {
			if r != replica(i+1) {
				return errors.New("invalid publisher manifest replica contract")
			}
		}
	}
	return nil
}

func (m Manifest) FindPublisher(name string) (Publisher, error) {
	if err := m.Validate(); err != nil {
		return Publisher{}, err
	}
	for _, p := range m.Publishers {
		if p.Name == name {
			return p, nil
		}
	}
	return Publisher{}, errors.New("publisher is not in the generated manifest; run tnl generate")
}

// Validate checks both saved artifact hashes and current evaluated configuration.
// bootstrap must call this before using any manifest identity references.
func Validate(outputDir string, configuration config.TNL, source projectconfig.SourceIdentity) (Manifest, error) {
	m, err := Read(outputDir)
	if err != nil {
		return m, err
	}
	expected, err := Generate(configuration, source)
	if err != nil {
		return m, err
	}
	infra := m
	infra.DeclarationsSHA256 = ""
	actual, err := encode(infra)
	if err != nil {
		return m, err
	}
	if !bytes.Equal(actual, expected.Files[ManifestPath]) {
		return m, errors.New("publisher manifest is stale; run tnl generate")
	}
	return m, nil
}
