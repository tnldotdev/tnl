package observability

//go:generate go run ./cmd/vocabulary ../../api/observability/v1/vocabulary.json

import (
	"context"
	"crypto/tls"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

// Key is an approved attribute name. the model here and instrument declarations
// generate vocabulary.json; that deterministic artifact is shared with tnl.dev.
type Key string

const (
	ServiceNamespace      Key = "service.namespace"
	ServiceName           Key = "service.name"
	ServiceVersion        Key = "service.version"
	ServiceInstanceID     Key = "service.instance.id"
	Environment           Key = "deployment.environment.name"
	RoleKey               Key = "tnl.role"
	CloudProvider         Key = "cloud.provider"
	CloudRegion           Key = "cloud.region"
	CloudAvailabilityZone Key = "cloud.availability_zone"
	TeamID                Key = "tnl.team_id"
	DeploymentID          Key = "tnl.deployment_id"
	ReplicaKey            Key = "tnl.replica_key"
	PublisherGroupID      Key = "tnl.publisher_group_id"
	PublisherIdentityID   Key = "tnl.publisher_identity_id"
	ServiceID             Key = "tnl.service_id"
	PublicURLID           Key = "tnl.public_url_id"
	ServiceKindKey        Key = "tnl.service_kind"
	Component             Key = "tnl.component"
	ServiceProtocol       Key = "tnl.service_protocol"
	Transport             Key = "tnl.transport"
	TransportPreference   Key = "tnl.transport_preference"
	AccessPath            Key = "tnl.access_path"
	Exposure              Key = "tnl.exposure"
	TLSLeg                Key = "tnl.tls_leg"
	ConnectionSlot        Key = "tnl.connection_slot"
	Direction             Key = "tnl.direction"
	Operation             Key = "tnl.operation"
	OutcomeKey            Key = "tnl.outcome"
	Reason                Key = "tnl.reason"
	ErrorType             Key = "error.type"
	State                 Key = "tnl.state"
	Event                 Key = "tnl.event"
	CertificateKind       Key = "tnl.certificate_kind"
	DNSKind               Key = "tnl.dns_kind"
	CleanupKind           Key = "tnl.cleanup_kind"
	CapacityResource      Key = "tnl.capacity_resource"
	HTTPMethod            Key = "http.request.method"
	HTTPStatus            Key = "http.response.status_code"
	HTTPRoute             Key = "http.route"
	TLSVersion            Key = "tls.protocol.version"
	TLSResumed            Key = "tls.resumed"
	ResponseOrigin        Key = "tnl.response_origin"
	VisitorConnectionID   Key = "tnl.visitor_connection_id"
	RequestID             Key = "tnl.request_id"
	PublishRunID          Key = "tnl.publish_run_id"
	PublishRunNumber      Key = "tnl.publish_run_number"
	PublisherConnectionID Key = "tnl.publisher_connection_id"
	GrantID               Key = "tnl.grant_id"
	ActorID               Key = "tnl.actor_id"
	Revision              Key = "tnl.revision"
	ImageHash             Key = "tnl.image_hash"
)

type Role string

const (
	RoleControl    Role = "control"
	RoleIngress    Role = "ingress"
	RoleRelay      Role = "relay"
	RoleStandalone Role = "standalone"
	RolePublisher  Role = "publisher"
	RoleClient     Role = "client"
	RoleAccounts   Role = "accounts"
	RoleCollector  Role = "collector"
)

type ServiceKind string

const (
	ManagedService ServiceKind = "managed_service"
	PublicURL      ServiceKind = "public_url"
)

// NormalizeServiceKind translates the private_service wire value at the boundary.
func NormalizeServiceKind(value string) ServiceKind {
	switch value {
	case "private_service", string(ManagedService):
		return ManagedService
	case string(PublicURL):
		return PublicURL
	default:
		return ""
	}
}

type Outcome string

const (
	Success  Outcome = "success"
	Denied   Outcome = "denied"
	Rejected Outcome = "rejected"
	Timeout  Outcome = "timeout"
	Canceled Outcome = "canceled"
	Error    Outcome = "error"
)

type AttributeDefinition struct {
	Key             Key      `json:"key"`
	Values          []string `json:"values,omitempty"`
	Semantics       string   `json:"semantics"`
	DimensionPolicy string   `json:"dimension_policy"`
}

// VocabularyAttributes is the shared key/value/semantics/dimension policy model.
func VocabularyAttributes() []AttributeDefinition {
	var out []AttributeDefinition
	add := func(k Key, policy, semantics string, values ...string) {
		out = append(out, AttributeDefinition{k, slices.Clone(values), semantics, policy})
	}
	add(ServiceNamespace, "resource", "fixed product namespace", "tnl")
	add(ServiceName, "resource", "process service, not a tenant or managed service", "tnld", "tnl", "tnl-accounts", "otel-collector")
	add(ServiceVersion, "resource", "binary or deployed application version")
	add(ServiceInstanceID, "resource", "unique runtime instance; random when unset, never a durable publisher identity")
	add(Environment, "resource", "operator-declared deployment environment; omitted when unknown")
	add(RoleKey, "resource", "configured process role", string(RoleControl), string(RoleIngress), string(RoleRelay), string(RoleStandalone), string(RolePublisher), string(RoleClient), string(RoleAccounts), string(RoleCollector))
	for _, k := range []Key{CloudProvider, CloudRegion, CloudAvailabilityZone} {
		add(k, "resource", "known operator-declared cloud fact; no metadata discovery")
	}
	for _, k := range []Key{TeamID, DeploymentID, ReplicaKey, PublisherGroupID, PublisherIdentityID, ServiceID, PublicURLID} {
		add(k, "scoped", "authenticated stable identity; instrument allowlist required; service_id and public_url_id are mutually exclusive")
	}
	add(ServiceKindKey, "scoped", "managed service or public URL; private_service wire value normalizes to managed_service", string(ManagedService), string(PublicURL))
	add(Component, "bounded", "component performing this work; independent of process role", "control", "authority", "private_ingress", "private_relay", "ingress", "relay", "publisher", "client", "accounts", "collector")
	add(ServiceProtocol, "bounded", "service application protocol", "http", "postgres", "mysql", "tcp")
	for _, k := range []Key{Transport, TransportPreference} {
		add(k, "bounded", "selected transport (omit when not selected), or initial preference", "quic", "tls-tcp")
	}
	add(AccessPath, "bounded", "visitor admission path", "connector", "direct")
	add(Exposure, "bounded", "service reachability", "private", "public")
	add(TLSLeg, "bounded", "TLS boundary owned by this observation", "visitor", "target")
	add(ConnectionSlot, "bounded", "assigned publisher connection slot; omitted when unknown", "0", "1")
	add(Direction, "bounded", "byte direction at the named component; wire bytes are distinct from target payload", "visitor_to_target", "target_to_visitor", "visitor_to_publisher", "publisher_to_visitor", "visitor_to_relay", "relay_to_visitor")
	add(Operation, "bounded", "compiled operation name; never supplied input, SQL, or a path")
	add(OutcomeKey, "bounded", "operation result; domain detail belongs in reason, state, or event", string(Success), string(Denied), string(Rejected), string(Timeout), string(Canceled), string(Error))
	add(Reason, "bounded", "closed domain reason from semantic result classification or lifecycle observer; never error text", append(domainReasons(), "expected", "unexpected", "stale_assignment", "publisher_unavailable", "failed_ready")...)
	add(ErrorType, "trace_log", "owned failure.Reason or diagnostic code only; unknown errors use unexpected")
	add(State, "bounded", "closed per-instrument readiness or state-machine value")
	add(Event, "bounded", "closed per-instrument lifecycle event, including queued, delivered, and dropped")
	add(CertificateKind, "bounded", "certificate worker domain", "public_url", "relay", "managed_service", "control")
	add(DNSKind, "bounded", "DNS worker domain", "authority", "public_url", "managed_service", "public_url_challenge", "relay_challenge")
	add(CleanupKind, "bounded", "cleanup domain", "expired_publish_runs", "ephemeral_public_urls", "routing_floor", "routing_prune", "service_audit", "guest_private_state")
	add(CapacityResource, "bounded", "admission capacity domain", admissionResources...)
	add(HTTPMethod, "bounded", "standard HTTP method; unknown methods normalize to _OTHER", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "_OTHER")
	add(HTTPStatus, "bounded", "HTTP response status code, 100 through 599")
	add(HTTPRoute, "bounded", "compiled matched route template only; never raw request path")
	add(TLSVersion, "bounded", "negotiated TLS version", "1.2", "1.3")
	add(TLSResumed, "bounded", "whether this TLS handshake resumed a session", "true", "false")
	add(ResponseOrigin, "bounded", "component authoring the HTTP response", "tnl", "local_service")
	for _, k := range []Key{VisitorConnectionID, RequestID, PublishRunID, PublishRunNumber, PublisherConnectionID, GrantID, ActorID, Revision, ImageHash} {
		add(k, "trace_log", "high-churn correlation only; prohibited as a metric dimension")
	}
	for _, k := range []Key{"tnl.connection_class", "tnl.stage", "tnl.phase", "tnl.action", "tnl.provider", "tnl.public_url_purpose", "tnl.domain_kind", "tnl.certificate_plan", "tnl.milestone", "tnl.ingress_pool", "tnl.database_purpose", "tnl.signal"} {
		add(k, "bounded", "closed domain value supplied by the owning semantic observer")
	}
	slices.SortFunc(out, func(a, b AttributeDefinition) int { return strings.Compare(string(a.Key), string(b.Key)) })
	return out
}

func (k Key) String(value string) attribute.KeyValue { return attribute.String(string(k), value) }
func (k Key) Int(value int) attribute.KeyValue       { return attribute.Int(string(k), value) }
func (k Key) Bool(value bool) attribute.KeyValue     { return attribute.Bool(string(k), value) }

// Fields narrows future streaming/TLS callers to this vocabulary without exposing
// metric instruments or accepting arbitrary attribute names. omitted values clear
// the previous field set; identity has its own authenticated scope API.
type Fields struct {
	Component           string
	ServiceProtocol     string
	Transport           string
	TransportPreference string
	AccessPath          string
	Exposure            string
	TLSLeg              string
	Direction           string
	ConnectionSlot      *int
	ResponseOrigin      string
}
type fieldsKey struct{}

func WithFields(ctx context.Context, fields Fields) context.Context {
	return context.WithValue(ctx, fieldsKey{}, fields)
}
func fieldAttributes(ctx context.Context) []attribute.KeyValue {
	f, _ := ctx.Value(fieldsKey{}).(Fields)
	var out []attribute.KeyValue
	for _, item := range []struct {
		k Key
		v string
	}{{Component, f.Component}, {ServiceProtocol, f.ServiceProtocol}, {Transport, f.Transport}, {TransportPreference, f.TransportPreference}, {AccessPath, f.AccessPath}, {Exposure, f.Exposure}, {TLSLeg, f.TLSLeg}, {Direction, f.Direction}, {ResponseOrigin, f.ResponseOrigin}} {
		if slices.Contains(attributeValues[item.k], item.v) {
			out = append(out, item.k.String(item.v))
		}
	}
	if f.ConnectionSlot != nil && (*f.ConnectionSlot == 0 || *f.ConnectionSlot == 1) {
		out = append(out, ConnectionSlot.Int(*f.ConnectionSlot))
	}
	return out
}

var admissionResources = []string{"client_hello_connections", "public_connections", "public_url_connections", "denied_connections", "denied_public_url_connections", "control_connections", "relay_tcp_connections", "publisher_connections", "relay_streams", "process_connection_rate", "source_connection_rate", "source_connections", "public_url_connection_rate", "public_url_connection_total", "pending_source_capacity", "pending_source_connections", "pending_public_url_connections", "pending_source_rate", "pending_public_url_rate", "traffic_keys", "traffic_bandwidth", "invalid_traffic_projection", "other"}

var attributeValues = func() map[Key][]string {
	out := make(map[Key][]string)
	for _, def := range VocabularyAttributes() {
		out[def.Key] = def.Values
	}
	return out
}()

func validMetricValue(kv attribute.KeyValue) bool {
	if values := attributeValues[Key(kv.Key)]; len(values) > 0 {
		return slices.Contains(values, kv.Value.String())
	}
	value := kv.Value.String()
	return len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

// Attributes selects only named scoped identity/protocol fields for a caller's
// instrument allowlist. trace-only correlation is deliberately unavailable here.
func Attributes(ctx context.Context, allowed ...Key) []attribute.KeyValue {
	var out []attribute.KeyValue
	for _, a := range append(identityAttributes(ctx), fieldAttributes(ctx)...) {
		if slices.Contains(allowed, Key(a.Key)) {
			out = append(out, a)
		}
	}
	return out
}

// TLSAttributes accepts negotiated state, never certificate subjects or peers.
func TLSAttributes(state tls.ConnectionState) []attribute.KeyValue {
	version := ""
	switch state.Version {
	case tls.VersionTLS12:
		version = "1.2"
	case tls.VersionTLS13:
		version = "1.3"
	}
	if version == "" {
		return nil
	}
	return []attribute.KeyValue{TLSVersion.String(version), TLSResumed.Bool(state.DidResume)}
}
