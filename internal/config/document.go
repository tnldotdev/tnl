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
	Name       *string              `json:"name,omitempty" yaml:"name,omitempty" jsonschema_description:"Saved name for an unnamed HTTP service; named services use their service key unless overridden."`
	Server     *string              `json:"server,omitempty" yaml:"server,omitempty" jsonschema_description:"Control URL used by this project."`
	Team       *string              `json:"team,omitempty" yaml:"team,omitempty" jsonschema_description:"Unique lowercase team name or team ID used by this project."`
	Feedback   *bool                `json:"feedback,omitempty" yaml:"feedback,omitempty" jsonschema_description:"Show the feedback toolbar on development pages."`
	OAuth      bool                 `json:"oauth,omitempty" yaml:"oauth,omitempty" jsonschema_description:"Publish one shared OAuth callback URL while project tunnels run."`
	Inspection *Inspection          `json:"inspection,omitempty" yaml:"inspection,omitempty" jsonschema_description:"Local inspection capture and retention for HTTP and supported TCP services."`
	Tunnel     *Tunnel              `json:"public_url,omitempty" yaml:"public_url,omitempty" jsonschema_description:"Defaults applied only to explicit services.NAME.public_url blocks. These defaults never enable a public URL for another service."`
	Publish    *Publish             `json:"-" yaml:"-"`
	Readiness  *Readiness           `json:"-" yaml:"-"`
	Publishers map[string]Publisher `json:"publishers,omitempty" yaml:"publishers,omitempty" jsonschema_description:"Named publisher groups with a durable namespace beneath a ready team domain. local is reserved for the built-in local publisher."`
	Services   Services             `json:"services,omitempty" yaml:"services,omitempty" jsonschema_description:"Named services. Only an explicit service public_url block enables public HTTPS; all other services are private, including HTTP."`
	Webhooks   map[string]Webhook   `json:"webhooks,omitempty" yaml:"webhooks,omitempty" jsonschema_description:"Stable project webhook endpoints, delivered to running worktrees."`
	Aliases    map[string]Alias     `json:"aliases,omitempty" yaml:"aliases,omitempty" jsonschema_description:"Saved project public URLs assigned to the primary checkout by default, or explicitly to another worktree."`
	Workloads  map[string]Workload  `json:"workloads,omitempty" yaml:"workloads,omitempty" jsonschema_description:"Named provider identities granting access to exact configured services."`
}

type Services map[string]Service

type Publisher struct {
	AWS         *PublisherAWS `json:"aws,omitempty" yaml:"aws,omitempty" jsonschema_description:"Generate one AWS Fargate group stack. Deployment parameters belong in CloudFormation, not project configuration."`
	Description *string       `json:"description,omitempty" yaml:"description,omitempty"`
	Domain      *string       `json:"domain,omitempty" yaml:"domain,omitempty" jsonschema_description:"Ready team domain; defaults to the team's default domain when the namespace is first allocated."`
	Public      bool          `json:"public,omitempty" yaml:"public,omitempty" jsonschema_description:"Enable direct ingress access. Omitted or false uses loopback DNS and requires tnl connect. Native TLS and visitor authorization apply in either mode."`
}

// MaxPublisherReplicas bounds generated stacks below CloudFormation quotas.
const MaxPublisherReplicas = 8

type PublisherAWS struct {
	Replicas *int `json:"replicas,omitempty" yaml:"replicas,omitempty"`
}

func (a PublisherAWS) ReplicaCount() int {
	if a.Replicas == nil {
		return 1
	}
	return *a.Replicas
}

// ServiceAccess declares a team grant for either a public or private service.
type ServiceAccess struct {
	Team bool `json:"team,omitempty" yaml:"team,omitempty"`
}

// Service contains project-local overrides for one named local service.
type Service struct {
	Name       *string        `json:"name,omitempty" yaml:"name,omitempty" jsonschema_description:"Saved name; defaults to the service key for both HTTP and private services."`
	Publisher  *string        `json:"publisher,omitempty" yaml:"publisher,omitempty" jsonschema_description:"Assigned publisher group; defaults to the built-in local publisher."`
	Access     *ServiceAccess `json:"access,omitempty" yaml:"access,omitempty" jsonschema_description:"Team grant intent for this service, whether public or private."`
	Inspection *Inspection    `json:"inspection,omitempty" yaml:"inspection,omitempty" jsonschema_description:"Override local inspection capture and retention for this service."`
	Tunnel     *Tunnel        `json:"public_url,omitempty" yaml:"public_url,omitempty" jsonschema_description:"Enable public HTTPS for this HTTP service. Omit this block for a private service, including private HTTP. The saved name belongs on the service."`
	Protocol   *string        `json:"protocol,omitempty" yaml:"protocol,omitempty" jsonschema:"enum=http,enum=tcp,enum=mysql,enum=postgres,enum=kubernetes" jsonschema_description:"Defaults to http. Protocol selects native client guidance, never public exposure or target TLS."`
	Target     *ServiceTarget `json:"target,omitempty" yaml:"target,omitempty"`
	HTTP       *HTTPService   `json:"http,omitempty" yaml:"http,omitempty"`
}

// TrustSource is an evaluated CA source, not a service configuration setting.
type TrustSource struct {
	Hostname *string `json:"hostname,omitempty" yaml:"hostname,omitempty" jsonschema_description:"Certificate hostname; defaults to the target host. Set this when dialing an IP whose certificate names a DNS host."`
	CA       string  `json:"ca" yaml:"ca"`
}

// ServiceName selects a saved name for either publication path.
func ServiceName(serviceName string, service Service) string {
	if service.Name != nil {
		return *service.Name
	}
	return serviceName
}

// PrivateServiceName selects the saved name for a validated private service.
func PrivateServiceName(serviceName string, service Service) string {
	return ServiceName(serviceName, service)
}

// ServiceTarget describes exactly one private discovery mechanism. an omitted
// target means an app-reported HTTP listener.
type ServiceTarget struct {
	Type      string     `json:"type" yaml:"type" jsonschema:"required,enum=app,enum=address,enum=compose,enum=docker,enum=eks,enum=rds"`
	Address   *Target    `json:"address,omitempty" yaml:"address,omitempty"`
	Project   *string    `json:"project,omitempty" yaml:"project,omitempty"`
	File      *string    `json:"file,omitempty" yaml:"file,omitempty"`
	Service   *string    `json:"service,omitempty" yaml:"service,omitempty"`
	Port      *int       `json:"port,omitempty" yaml:"port,omitempty"`
	Container *string    `json:"container,omitempty" yaml:"container,omitempty"`
	TLS       *TargetTLS `json:"tls,omitempty" yaml:"tls,omitempty"`
	Region    *string    `json:"region,omitempty" yaml:"region,omitempty"`
	Cluster   *string    `json:"cluster,omitempty" yaml:"cluster,omitempty"`
	Instance  *string    `json:"instance,omitempty" yaml:"instance,omitempty"`
	Endpoint  *string    `json:"endpoint,omitempty" yaml:"endpoint,omitempty" jsonschema:"enum=writer,enum=reader"`
}

type TargetTLS struct {
	ServerName *string `json:"server_name,omitempty" yaml:"server_name,omitempty" jsonschema_description:"Target certificate hostname or IP; defaults to the resolved target host. Independent of the managed visitor TLS identity."`
	CAFile     *string `json:"ca_file,omitempty" yaml:"ca_file,omitempty" jsonschema_description:"Project-relative CA-only PEM file added to system roots. Omit to use system roots. The publisher verifies target TLS; postgres and mysql use native negotiation, http and tcp use direct TLS. No unverified or plaintext fallback."`
}

type HTTPService struct {
	Readiness *Readiness           `json:"readiness,omitempty" yaml:"readiness,omitempty" jsonschema_description:"Readiness probe for a local HTTP service. Remote publisher assignments do not support readiness overrides."`
	Paths     map[string]PathMount `json:"paths,omitempty" yaml:"paths,omitempty" jsonschema_description:"Path mounts between local HTTP services. Remote publisher assignments do not support path mounts."`
	Open      *bool                `json:"open,omitempty" yaml:"open,omitempty"`
}

func ServicePaths(service Service) map[string]PathMount {
	if service.HTTP == nil {
		return nil
	}
	return service.HTTP.Paths
}

func TargetType(service Service) string {
	if service.Target == nil {
		return "app"
	}
	return service.Target.Type
}

func Protocol(service Service) string {
	if service.Protocol == nil {
		return "http"
	}
	return *service.Protocol
}

func IsPublicService(service Service) bool { return service.Tunnel != nil }

func PublisherName(service Service) string {
	if service.Publisher == nil {
		return "local"
	}
	return *service.Publisher
}

// ServicePublish resolves address targets into the native publication settings.
// compose and docker addresses must first be discovered by the runtime.
func ServicePublish(service Service) *Publish {
	protocol := Protocol(service)
	result := &Publish{Protocol: &protocol}
	if service.Target == nil {
		return result
	}
	result.Target = service.Target.Address
	if tls := service.Target.TLS; tls != nil {
		result.TargetTLSName, result.TargetCAFile = tls.ServerName, tls.CAFile
		enabled := true
		result.TargetTLS = &enabled
	}
	return result
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
	Domain    *string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Name      *string `json:"-" yaml:"-"`
	PublicURL *string `json:"hostname,omitempty" yaml:"hostname,omitempty" jsonschema_description:"Exact authorized public hostname or HTTPS origin. Mutually exclusive with the service's name override."`
	Open      *bool   `json:"-" yaml:"-"`
	Access    *Access `json:"access,omitempty" yaml:"access,omitempty"`
	Ephemeral *bool   `json:"ephemeral,omitempty" yaml:"ephemeral,omitempty"`
	Limits    *Limits `json:"limits,omitempty" yaml:"limits,omitempty"`
}

// Limits apply to application requests after visitor access.
type Limits struct {
	HTTP    *WorkLimits    `json:"http,omitempty" yaml:"http,omitempty"`
	TCP     *WorkLimits    `json:"tcp,omitempty" yaml:"tcp,omitempty"`
	Traffic *TrafficLimits `json:"traffic,omitempty" yaml:"traffic,omitempty"`
}

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

// TrafficLimits selects independent ingress connection and directional byte budgets.
type TrafficLimits struct {
	Connections        *int      `json:"connections,omitempty" yaml:"connections,omitempty"`
	Rate               *int      `json:"rate,omitempty" yaml:"rate,omitempty"`
	RatePer            *Duration `json:"rate_per,omitempty" yaml:"rate_per,omitempty"`
	Burst              *int      `json:"burst,omitempty" yaml:"burst,omitempty"`
	UploadBytes        *int64    `json:"upload_bytes,omitempty" yaml:"upload_bytes,omitempty"`
	DownloadBytes      *int64    `json:"download_bytes,omitempty" yaml:"download_bytes,omitempty"`
	TotalConnections   *int64    `json:"total_connections,omitempty" yaml:"total_connections,omitempty"`
	TotalUploadBytes   *int64    `json:"total_upload_bytes,omitempty" yaml:"total_upload_bytes,omitempty"`
	TotalDownloadBytes *int64    `json:"total_download_bytes,omitempty" yaml:"total_download_bytes,omitempty"`
}

type Publish struct {
	Protocol      *string `json:"protocol,omitempty" yaml:"protocol,omitempty" jsonschema:"enum=http,enum=tcp,enum=mysql,enum=postgres" jsonschema_description:"Service protocol; defaults to http."`
	Target        *Target `json:"target,omitempty" yaml:"target,omitempty" jsonschema_description:"HTTP or HTTPS origin, local port, or TCP host:port reached by the publisher."`
	TargetTLSName *string `json:"target_tls_name,omitempty" yaml:"target_tls_name,omitempty" jsonschema_description:"Hostname expected in the target's TLS certificate; defaults to the target host."`
	TargetTLS     *bool   `json:"target_tls,omitempty" yaml:"target_tls,omitempty" jsonschema_description:"Use verified TLS for the TCP target."`
	TargetCAFile  *string `json:"target_ca_file,omitempty" yaml:"target_ca_file,omitempty" jsonschema_description:"Additional PEM certificate authorities for the target; relative paths are resolved from the project root."`
}

// ServiceProtocol selects the service protocol, defaulting to http.
func ServiceProtocol(publish *Publish) string {
	if publish != nil && publish.Protocol != nil {
		return *publish.Protocol
	}
	return "http"
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

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.Value().String()) }

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
		if err := validateYAMLValueTypes(valueNode, field.typ, make(map[*yaml.Node]bool)); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
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
	typ      reflect.Type
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
			tnldFieldMap[name] = tnldField{index: index, typ: field.Type, duration: field.Type == durationType}
		}
	})
	return tnldFieldMap
}
