package observability

import "go.opentelemetry.io/otel/attribute"

// Key is a catalog name, not an attribute constructor. the private handle
// representation also prevents changing an inferred handle's name with a literal.
type Key string

type attributeKey interface{ key() Key }

// MetricKey is sealed: resource-only, SDK, and trace/log-only handles do not implement it.
type MetricKey interface {
	attributeKey
	metricKey()
}

type keyName struct{ name Key }

func (k keyName) key() Key { return k.name }
func (k keyName) Key() Key { return k.name }

type stringKey struct{ keyName }
type intKey struct{ keyName }
type boolKey struct{ keyName }
type metricStringKey struct{ keyName }
type metricIntKey struct{ keyName }
type metricBoolKey struct{ keyName }
type metricEnumKey[T interface{ String() string }] struct{ keyName }

func (metricStringKey) metricKey()  {}
func (metricIntKey) metricKey()     {}
func (metricBoolKey) metricKey()    {}
func (metricEnumKey[T]) metricKey() {}

func (k stringKey) String(v string) attribute.KeyValue { return attribute.String(string(k.name), v) }
func (k intKey) Int(v int) attribute.KeyValue          { return attribute.Int(string(k.name), v) }
func (k boolKey) Bool(v bool) attribute.KeyValue       { return attribute.Bool(string(k.name), v) }
func (k metricStringKey) String(v string) attribute.KeyValue {
	return attribute.String(string(k.name), v)
}
func (k metricIntKey) Int(v int) attribute.KeyValue    { return attribute.Int(string(k.name), v) }
func (k metricBoolKey) Bool(v bool) attribute.KeyValue { return attribute.Bool(string(k.name), v) }
func (k metricEnumKey[T]) Value(v T) attribute.KeyValue {
	return attribute.String(string(k.name), v.String())
}

// Dimension is a named metric value. its private representation prevents an OTel
// attribute (including a trace-only identifier) from entering a metric binding.
type Dimension struct{ attrs []attribute.KeyValue }

func (k metricStringKey) Dimension(v string) Dimension {
	return Dimension{[]attribute.KeyValue{k.String(v)}}
}
func (k metricIntKey) Dimension(v int) Dimension   { return Dimension{[]attribute.KeyValue{k.Int(v)}} }
func (k metricBoolKey) Dimension(v bool) Dimension { return Dimension{[]attribute.KeyValue{k.Bool(v)}} }
func (k metricEnumKey[T]) Dimension(v T) Dimension {
	return Dimension{[]attribute.KeyValue{k.Value(v)}}
}

var (
	ServiceNamespace       = stringKey{keyName{"service.namespace"}}
	ServiceName            = stringKey{keyName{"service.name"}}
	ServiceVersion         = stringKey{keyName{"service.version"}}
	ServiceInstanceID      = stringKey{keyName{"service.instance.id"}}
	Environment            = stringKey{keyName{"deployment.environment.name"}}
	RoleKey                = metricEnumKey[Role]{keyName{"tnl.role"}}
	CloudProvider          = stringKey{keyName{"cloud.provider"}}
	CloudRegion            = stringKey{keyName{"cloud.region"}}
	RegionKey              = stringKey{keyName{"tnl.region"}}
	IngressRegion          = metricStringKey{keyName{"tnl.ingress_region"}}
	RelayRegion            = metricStringKey{keyName{"tnl.relay_region"}}
	CloudAvailabilityZone  = stringKey{keyName{"cloud.availability_zone"}}
	TeamID                 = metricStringKey{keyName{"tnl.team_id"}}
	DeploymentID           = metricStringKey{keyName{"tnl.deployment_id"}}
	ReplicaKey             = metricStringKey{keyName{"tnl.replica_key"}}
	PublisherGroupID       = metricStringKey{keyName{"tnl.publisher_group_id"}}
	PublisherIdentityID    = metricStringKey{keyName{"tnl.publisher_identity_id"}}
	ServiceID              = metricStringKey{keyName{"tnl.service_id"}}
	PublicURLID            = metricStringKey{keyName{"tnl.public_url_id"}}
	ServiceKindKey         = metricEnumKey[ServiceKind]{keyName{"tnl.service_kind"}}
	Component              = metricStringKey{keyName{"tnl.component"}}
	ServiceProtocol        = metricEnumKey[Protocol]{keyName{"tnl.service_protocol"}}
	KubernetesVerb         = stringKey{keyName{"tnl.kubernetes_verb"}}
	KubernetesAPIGroup     = stringKey{keyName{"tnl.kubernetes_api_group"}}
	KubernetesResource     = stringKey{keyName{"tnl.kubernetes_resource"}}
	KubernetesSubresource  = stringKey{keyName{"tnl.kubernetes_subresource"}}
	Transport              = metricEnumKey[TransportValue]{keyName{"tnl.transport"}}
	TransportPreference    = metricEnumKey[TransportValue]{keyName{"tnl.transport_preference"}}
	AccessPath             = metricStringKey{keyName{"tnl.access_path"}}
	Exposure               = metricStringKey{keyName{"tnl.exposure"}}
	TLSLeg                 = metricStringKey{keyName{"tnl.tls_leg"}}
	ConnectionSlot         = metricIntKey{keyName{"tnl.connection_slot"}}
	Direction              = metricStringKey{keyName{"tnl.direction"}}
	Operation              = metricEnumKey[operationName]{keyName{"tnl.operation"}}
	OutcomeKey             = metricEnumKey[Outcome]{keyName{"tnl.outcome"}}
	Reason                 = metricStringKey{keyName{"tnl.reason"}}
	ErrorType              = stringKey{keyName{"error.type"}}
	State                  = metricEnumKey[LifecycleState]{keyName{"tnl.state"}}
	Event                  = metricEnumKey[LifecycleEvent]{keyName{"tnl.event"}}
	CertificateKind        = metricStringKey{keyName{"tnl.certificate_kind"}}
	DNSKind                = metricStringKey{keyName{"tnl.dns_kind"}}
	CleanupKind            = metricStringKey{keyName{"tnl.cleanup_kind"}}
	CapacityResource       = metricStringKey{keyName{"tnl.capacity_resource"}}
	HTTPMethod             = metricStringKey{keyName{"http.request.method"}}
	HTTPStatus             = metricIntKey{keyName{"http.response.status_code"}}
	HTTPRoute              = metricStringKey{keyName{"http.route"}}
	TLSVersion             = metricStringKey{keyName{"tls.protocol.version"}}
	TLSResumed             = metricBoolKey{keyName{"tls.resumed"}}
	ResponseOrigin         = metricStringKey{keyName{"tnl.response_origin"}}
	VisitorConnectionID    = stringKey{keyName{"tnl.visitor_connection_id"}}
	RequestID              = stringKey{keyName{"tnl.request_id"}}
	PublishRunID           = stringKey{keyName{"tnl.publish_run_id"}}
	PublishRunNumber       = intKey{keyName{"tnl.publish_run_number"}}
	PublisherConnectionID  = stringKey{keyName{"tnl.publisher_connection_id"}}
	GrantID                = stringKey{keyName{"tnl.grant_id"}}
	ActorID                = stringKey{keyName{"tnl.actor_id"}}
	Revision               = intKey{keyName{"tnl.revision"}}
	ImageHash              = stringKey{keyName{"tnl.image_hash"}}
	MetricOverflow         = boolKey{keyName{"otel.metric.overflow"}}
	WorkloadSessionID      = stringKey{keyName{"tnl.workload_session_id"}}
	WorkloadRunID          = stringKey{keyName{"tnl.workload_run_id"}}
	WorkloadRunAttempt     = stringKey{keyName{"tnl.workload_run_attempt"}}
	WorkloadCheckRunID     = stringKey{keyName{"tnl.workload_check_run_id"}}
	targetProvider         = metricStringKey{keyName{"tnl.target_provider"}}
	targetType             = metricStringKey{keyName{"tnl.target_type"}}
	targetDiscoveryOutcome = metricStringKey{keyName{"tnl.target_discovery_outcome"}}
	targetResourceARN      = stringKey{keyName{"tnl.target_resource_arn"}}
	targetResourceID       = stringKey{keyName{"tnl.target_resource_id"}}
	connectionClass        = metricStringKey{keyName{"tnl.connection_class"}}
	providerKey            = metricStringKey{keyName{"tnl.provider"}}
	publicURLPurpose       = metricStringKey{keyName{"tnl.public_url_purpose"}}
	domainKind             = metricStringKey{keyName{"tnl.domain_kind"}}
	certificatePlan        = metricStringKey{keyName{"tnl.certificate_plan"}}
	ingresspool            = metricStringKey{keyName{"tnl.ingress_pool"}}
	databasePurpose        = metricStringKey{keyName{"tnl.database_purpose"}}
	signalKey              = metricStringKey{keyName{"tnl.signal"}}
)
