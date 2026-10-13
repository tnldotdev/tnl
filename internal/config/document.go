package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"go.yaml.in/yaml/v3"
)

const DocumentVersion = 1

// Document is the versioned static tnl.yml, tnl.yaml, or tnl.json contract.
// TypeScript configuration evaluates directly to the TnlConfig shape and is
// wrapped in this document shape by the loader.
type Document struct {
	Schema  string       `json:"$schema,omitempty" yaml:"$schema,omitempty" jsonschema_description:"JSON Schema URL used by editors and validation tools."`
	Version *int         `json:"version" yaml:"version" jsonschema:"required" jsonschema_description:"Configuration format version. Must be 1."`
	TNL     *TNL         `json:"tnl,omitempty" yaml:"tnl,omitempty" jsonschema_description:"Project configuration used by the tnl client."`
	TNLD    *TNLDSection `json:"tnld,omitempty" yaml:"tnld,omitempty" jsonschema_description:"Process configuration used by tnld."`
}

// TNL contains project-local client configuration.
type TNL struct {
	Server     *string            `json:"server,omitempty" yaml:"server,omitempty" jsonschema_description:"Control URL used by this project."`
	Team       *string            `json:"team,omitempty" yaml:"team,omitempty" jsonschema_description:"Unique lowercase team name or team ID used by this project."`
	Feedback   *bool              `json:"feedback,omitempty" yaml:"feedback,omitempty" jsonschema_description:"Show the feedback toolbar on development pages."`
	OAuth      bool               `json:"oauth,omitempty" yaml:"oauth,omitempty" jsonschema_description:"Publish one shared OAuth callback URL while project tunnels run."`
	Inspection *Inspection        `json:"inspection,omitempty" yaml:"inspection,omitempty" jsonschema_description:"Local inspection capture and retention for HTTP and database services."`
	Tunnel     *Tunnel            `json:"tunnel,omitempty" yaml:"tunnel,omitempty" jsonschema_description:"Default public URL and tunnel settings."`
	Publish    *Publish           `json:"-" yaml:"-"`
	Publisher  *ProjectPublisher  `json:"publisher,omitempty" yaml:"publisher,omitempty" jsonschema_description:"Publisher selected for this project; omitted uses the local host publisher."`
	Readiness  *Readiness         `json:"-" yaml:"-"`
	Services   Services           `json:"services,omitempty" yaml:"services,omitempty" jsonschema_description:"Named local services with a private target, public URL settings, and optional HTTP settings."`
	Webhooks   map[string]Webhook `json:"webhooks,omitempty" yaml:"webhooks,omitempty" jsonschema_description:"Stable project webhook endpoints, delivered to running worktrees."`
	Aliases    map[string]Alias   `json:"aliases,omitempty" yaml:"aliases,omitempty" jsonschema_description:"Saved project public URLs assigned to the primary checkout by default, or explicitly to another worktree."`
}

type Services map[string]Service

const DefaultPublisherOwnerCredentialFile = ".tnl/publisher-owner"

func (p ProjectPublisher) CredentialFile() string {
	if p.OwnerCredentialFile == nil {
		return DefaultPublisherOwnerCredentialFile
	}
	return *p.OwnerCredentialFile
}

// ProjectPublisher selects the project publisher's local or external API.
type ProjectPublisher struct {
	Type                string  `json:"type" yaml:"type" jsonschema:"required,enum=local,enum=docker,enum=url"`
	URL                 *string `json:"url,omitempty" yaml:"url,omitempty" jsonschema_description:"HTTPS origin of an external publisher API."`
	DockerSelection     `yaml:",inline"`
	OwnerCredentialFile *string `json:"owner_credential_file,omitempty" yaml:"owner_credential_file,omitempty" jsonschema_description:"Private file containing the project publisher owner credential; never browser metadata."`
}

// DockerSelection selects one private container port by an explicit Docker
// container, a worktree label, or a service in a specific Compose project.
type DockerSelection struct {
	Container     *string           `json:"container,omitempty" yaml:"container,omitempty"`
	Labels        map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Compose       *ComposeSelection `json:"compose,omitempty" yaml:"compose,omitempty"`
	ContainerPort *int              `json:"container_port,omitempty" yaml:"container_port,omitempty" jsonschema:"minimum=1,maximum=65535"`
}

type ComposeSelection struct {
	File    string `json:"file" yaml:"file"`
	Project string `json:"project" yaml:"project"`
	Service string `json:"service" yaml:"service"`
}

// Service contains project-local overrides for one named local service.
type Service struct {
	Inspection *Inspection          `json:"inspection,omitempty" yaml:"inspection,omitempty" jsonschema_description:"Override local inspection capture and retention for this service."`
	Directory  *string              `json:"-" yaml:"-"`
	Protocol   *string              `json:"protocol,omitempty" yaml:"protocol,omitempty" jsonschema:"enum=http,enum=postgres,enum=mysql,enum=redis,enum=ssh" jsonschema_description:"Local service protocol; defaults to http."`
	Target     *ServiceTarget       `json:"target,omitempty" yaml:"target,omitempty" jsonschema_description:"How the publisher finds this service."`
	HTTP       *HTTPService         `json:"http,omitempty" yaml:"http,omitempty" jsonschema_description:"HTTP path mounts and browser opening."`
	TCP        *TCPService          `json:"tcp,omitempty" yaml:"tcp,omitempty"`
	Tunnel     *Tunnel              `json:"tunnel,omitempty" yaml:"tunnel,omitempty" jsonschema_description:"PublicURL and tunnel overrides for this service."`
	Publish    *Publish             `json:"-" yaml:"-"`
	Readiness  *Readiness           `json:"readiness,omitempty" yaml:"readiness,omitempty"`
	Paths      map[string]PathMount `json:"-" yaml:"-"`
}

// ServiceTarget chooses an app listener, private address, or Compose service.
type ServiceTarget struct {
	Type            string  `json:"type" yaml:"type" jsonschema:"required,enum=app,enum=address,enum=docker"`
	Address         *Target `json:"address,omitempty" yaml:"address,omitempty" jsonschema_description:"Private HTTP origin, TCP host:port, or local port reached by the publisher."`
	DockerSelection `yaml:",inline"`
	TLS             *TargetTLS `json:"tls,omitempty" yaml:"tls,omitempty"`
}

type HTTPService struct {
	Open  *bool                `json:"open,omitempty" yaml:"open,omitempty"`
	Paths map[string]PathMount `json:"paths,omitempty" yaml:"paths,omitempty"`
}

// TCPService selects visitor TLS behavior for PostgreSQL and MySQL.
type TCPService struct {
	VisitorTLS *string `json:"visitor_tls,omitempty" yaml:"visitor_tls,omitempty" jsonschema:"enum=terminate,enum=passthrough"`
}

// TargetTLS enables verified TLS to a private target.
type TargetTLS struct {
	ServerName *string `json:"server_name,omitempty" yaml:"server_name,omitempty"`
	CAFile     *string `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
}

// ServicePaths returns the HTTP mounts for a named service.
func ServicePaths(service Service) map[string]PathMount {
	if service.HTTP != nil {
		return service.HTTP.Paths
	}
	return service.Paths
}

// PathMount selects a local service reached at a path on another service's public URL.
type PathMount struct {
	Service     string `json:"service" yaml:"service"`
	StripPrefix bool   `json:"strip_prefix,omitempty" yaml:"strip_prefix,omitempty"`
}

func (m *PathMount) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		*m = PathMount{Service: name}
		return nil
	}
	type object PathMount
	var value object
	if err := json.Unmarshal(data, &value, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("path mount must be a service name or an object: %w", err)
	}
	*m = PathMount(value)
	return nil
}

func (m *PathMount) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*m = PathMount{Service: node.Value}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("path mount must be a service name or an object")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "service", "strip_prefix":
		default:
			return fmt.Errorf("unknown path mount field %q", node.Content[index].Value)
		}
	}
	type object PathMount
	var value object
	if err := node.Decode(&value); err != nil {
		return err
	}
	*m = PathMount(value)
	return nil
}

type Tunnel struct {
	Domain      *string  `json:"domain,omitempty" yaml:"domain,omitempty"`
	Name        *string  `json:"name,omitempty" yaml:"name,omitempty"`
	PublicURL   *string  `json:"public_url,omitempty" yaml:"public_url,omitempty"`
	Open        *bool    `json:"-" yaml:"-"`
	AllowIP     []string `json:"allow_ip,omitempty" yaml:"allow_ip,omitempty" jsonschema:"uniqueItems=true"`
	AllowAllIPs *bool    `json:"allow_all_ips,omitempty" yaml:"allow_all_ips,omitempty"`
	Ephemeral   *bool    `json:"ephemeral,omitempty" yaml:"ephemeral,omitempty"`
	VisitorTLS  *string  `json:"-" yaml:"-"`
	Limits      *Limits  `json:"limits,omitempty" yaml:"limits,omitempty"`
}

// Limits select protocol-specific application admission after visitor access.
type Limits struct {
	Traffic *TrafficLimits `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	HTTP    *WorkLimits    `json:"http,omitempty" yaml:"http,omitempty"`
	TCP     *WorkLimits    `json:"tcp,omitempty" yaml:"tcp,omitempty"`
}

// TrafficLimits selects ingress admission for one publish run, independently
// of the HTTP request or TCP session budget in the local publisher.
type TrafficLimits struct {
	Connections *int       `json:"connections,omitempty" yaml:"connections,omitempty"`
	Rate        *Rate      `json:"rate,omitempty" yaml:"rate,omitempty"`
	Bandwidth   *Bandwidth `json:"bandwidth,omitempty" yaml:"bandwidth,omitempty"`
}

type Bandwidth struct {
	Upload   *ByteRate `json:"upload,omitempty" yaml:"upload,omitempty"`
	Download *ByteRate `json:"download,omitempty" yaml:"download,omitempty"`
}

// ByteRate is a positive, binary byte count per second.
type ByteRate string

type WorkLimits struct {
	Total       *int  `json:"total,omitempty" yaml:"total,omitempty"`
	Rate        *Rate `json:"rate,omitempty" yaml:"rate,omitempty"`
	Concurrency *int  `json:"concurrency,omitempty" yaml:"concurrency,omitempty"`
}

type Rate struct {
	Count *int      `json:"count,omitempty" yaml:"count,omitempty"`
	Per   *Duration `json:"per,omitempty" yaml:"per,omitempty"`
	Burst *int      `json:"burst,omitempty" yaml:"burst,omitempty"`
}

type Publish struct {
	Protocol      *string `json:"protocol,omitempty" yaml:"protocol,omitempty" jsonschema:"enum=http,enum=postgres,enum=mysql,enum=redis,enum=ssh" jsonschema_description:"Local service protocol: http (default), postgres, mysql, redis, or ssh."`
	Target        *Target `json:"target,omitempty" yaml:"target,omitempty" jsonschema_description:"HTTP or HTTPS origin, local port, or private TCP host:port reached by the publisher."`
	TargetTLSName *string `json:"target_tls_name,omitempty" yaml:"target_tls_name,omitempty" jsonschema_description:"Hostname expected in the private target TLS certificate; defaults to the target host."`
	TargetTLS     *bool   `json:"target_tls,omitempty" yaml:"target_tls,omitempty" jsonschema_description:"Use verified TLS for the private TCP target."`
	TargetCAFile  *string `json:"target_ca_file,omitempty" yaml:"target_ca_file,omitempty" jsonschema_description:"Additional PEM certificate authorities for the target; relative paths are resolved from the project root."`
}

// ServiceProtocol selects the public URL's service protocol, defaulting to http.
func ServiceProtocol(publish *Publish) string {
	if publish != nil && publish.Protocol != nil {
		return *publish.Protocol
	}
	return "http"
}

// ServicePublish resolves a named service's protocol and private target settings.
// a reported app listener has no configured target to inherit.
func ServicePublish(base *Publish, service Service) *Publish {
	result := MergePublish(base, service.Publish)
	if service.Protocol != nil {
		if result == nil {
			result = &Publish{}
		}
		result.Protocol = service.Protocol
	}
	if service.Target == nil {
		return result
	}
	if result == nil {
		result = &Publish{}
	}
	if service.Target.Type == "app" {
		result.Target = nil
		result.TargetTLS, result.TargetTLSName, result.TargetCAFile = nil, nil, nil
	} else if service.Target.Type == "address" {
		result.Target = service.Target.Address
	} else {
		result.Target = nil
	}
	if service.Target.Type != "app" {
		result.TargetTLS, result.TargetTLSName, result.TargetCAFile = nil, nil, nil
		if service.Target.TLS != nil {
			if ServiceProtocol(result) != "http" {
				enabled := true
				result.TargetTLS = &enabled
			}
			result.TargetTLSName = service.Target.TLS.ServerName
			result.TargetCAFile = service.Target.TLS.CAFile
		}
	}
	return result
}

// MergePublish applies one service's publish settings over the project defaults.
func MergePublish(base, override *Publish) *Publish {
	if base == nil && override == nil {
		return nil
	}
	result := &Publish{}
	if base != nil {
		*result = *base
	}
	if override == nil {
		return result
	}
	if override.Protocol != nil {
		result.Protocol = override.Protocol
	}
	if override.Target != nil {
		result.Target = override.Target
		result.TargetTLSName, result.TargetCAFile = nil, nil
		result.TargetTLS = nil
	}
	if override.TargetTLSName != nil {
		result.TargetTLSName = override.TargetTLSName
	}
	if override.TargetTLS != nil {
		result.TargetTLS = override.TargetTLS
	}
	if override.TargetCAFile != nil {
		result.TargetCAFile = override.TargetCAFile
	}
	return result
}

// readiness selects the public GET used to check one app publication.
type Readiness struct {
	Path string `json:"path" yaml:"path" jsonschema:"required"`
}

// Target accepts an HTTP or HTTPS origin or a literal local port.
type Target string

func (t *Target) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*t = Target(text)
		return nil
	}
	var port int
	if err := json.Unmarshal(data, &port); err != nil {
		return errors.New("target must be a string or integer port")
	}
	*t = Target(strconv.Itoa(port))
	return nil
}

func (t *Target) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("target must be a string or integer port")
	}
	if node.Tag == "!!int" {
		var port int
		if err := node.Decode(&port); err != nil {
			return errors.New("target must be a string or integer port")
		}
		*t = Target(strconv.Itoa(port))
		return nil
	}
	if node.Tag != "!!str" {
		return errors.New("target must be a string or integer port")
	}
	*t = Target(node.Value)
	return nil
}

// DurationPattern describes the positive Go duration syntax accepted by
// project configuration. semantic bounds are checked after decoding.
const DurationPattern = `^([0-9]+(\.[0-9]+)?|\.[0-9]+)(ns|us|\u00b5s|ms|s|m|h)(([0-9]+(\.[0-9]+)?|\.[0-9]+)(ns|us|\u00b5s|ms|s|m|h))*$`

var durationSyntax = regexp.MustCompile(strings.ReplaceAll(DurationPattern, `\u00b5`, `\x{00b5}`))

// Duration is a Go duration string in project configuration.
type Duration time.Duration

func (d Duration) Value() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string")
	}
	parsed, err := parseDuration(value)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("duration must be a string")
	}
	parsed, err := parseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func parseDuration(value string) (Duration, error) {
	if !durationSyntax.MatchString(value) {
		return 0, errors.New("invalid duration syntax")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %w", err)
	}
	return Duration(parsed), nil
}

// TNLDSection is a presence-aware partial tnldconfig.Config value. its field
// names and types are derived from Config so file configuration cannot drift
// from flags.
type TNLDSection struct {
	value   tnldconfig.Config
	present map[int]bool
}

func (s TNLDSection) Value() tnldconfig.Config { return s.value }

// Apply replaces only fields explicitly present in the file.
func (s TNLDSection) Apply(target *tnldconfig.Config) {
	s.apply(target, nil, false)
}

// ApplyLowerPrecedence applies file fields unless a command-line flag or one
// of the field's TNLD_* environment variables supplied a higher-precedence value.
func (s TNLDSection) ApplyLowerPrecedence(target *tnldconfig.Config, commandLine map[string]bool) map[string]bool {
	return s.apply(target, commandLine, true)
}

func (s TNLDSection) apply(target *tnldconfig.Config, commandLine map[string]bool, respectHigherPrecedence bool) map[string]bool {
	applied := make(map[string]bool)
	if target == nil {
		return applied
	}
	sourceValue := reflect.ValueOf(s.value)
	targetValue := reflect.ValueOf(target).Elem()
	typeOfConfig := reflect.TypeOf(tnldconfig.Config{})
	for index := range s.present {
		field := typeOfConfig.Field(index)
		name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
		if respectHigherPrecedence && (commandLine[name] || environmentConfigured(field.Tag.Get("env"))) {
			continue
		}
		targetValue.Field(index).Set(sourceValue.Field(index))
		applied[name] = true
	}
	return applied
}

func environmentConfigured(names string) bool {
	for _, name := range strings.Split(names, ",") {
		if name != "" {
			if _, ok := os.LookupEnv(name); ok {
				return true
			}
		}
	}
	return false
}

func (s *TNLDSection) UnmarshalJSON(data []byte) error {
	var values map[string]jsontext.Value
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	for name, data := range values {
		field, ok := tnldFields()[name]
		if !ok {
			return fmt.Errorf("unknown tnld field %q", name)
		}
		value := reflect.ValueOf(&s.value).Elem().Field(field.index)
		if field.duration {
			var text string
			if err := json.Unmarshal(data, &text); err != nil {
				return fmt.Errorf("tnld.%s must be a duration string", name)
			}
			parsed, err := time.ParseDuration(text)
			if err != nil {
				return fmt.Errorf("tnld.%s: invalid duration", name)
			}
			value.SetInt(int64(parsed))
		} else if err := json.Unmarshal(data, value.Addr().Interface(), json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
		}
		s.markPresent(field.index)
	}
	return nil
}

func (s *TNLDSection) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("tnld must be an object")
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key, valueNode := node.Content[index], node.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return errors.New("tnld field names must be strings")
		}
		name := key.Value
		if _, ok := seen[name]; ok {
			return fmt.Errorf("tnld field %q is duplicated", name)
		}
		seen[name] = struct{}{}
		field, ok := tnldFields()[name]
		if !ok {
			return fmt.Errorf("unknown tnld field %q", name)
		}
		value := reflect.ValueOf(&s.value).Elem().Field(field.index)
		if field.duration {
			if valueNode.Kind != yaml.ScalarNode || valueNode.Tag != "!!str" {
				return fmt.Errorf("tnld.%s must be a duration string", name)
			}
			parsed, err := time.ParseDuration(valueNode.Value)
			if err != nil {
				return fmt.Errorf("tnld.%s: invalid duration", name)
			}
			value.SetInt(int64(parsed))
		} else if err := valueNode.Decode(value.Addr().Interface()); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
		}
		s.markPresent(field.index)
	}
	return nil
}

func (s *TNLDSection) markPresent(index int) {
	if s.present == nil {
		s.present = make(map[int]bool)
	}
	s.present[index] = true
}

type tnldField struct {
	index    int
	duration bool
}

var (
	tnldFieldsOnce sync.Once
	tnldFieldMap   map[string]tnldField
)

func tnldFields() map[string]tnldField {
	tnldFieldsOnce.Do(func() {
		typeOfConfig := reflect.TypeOf(tnldconfig.Config{})
		durationType := reflect.TypeOf(time.Duration(0))
		tnldFieldMap = make(map[string]tnldField, typeOfConfig.NumField())
		for index := 0; index < typeOfConfig.NumField(); index++ {
			field := typeOfConfig.Field(index)
			name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
			if name == "" || name == "database_direct_url" {
				continue
			}
			tnldFieldMap[name] = tnldField{index: index, duration: field.Type == durationType}
		}
	})
	return tnldFieldMap
}
