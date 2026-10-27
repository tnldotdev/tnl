package observability

import (
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type AttributeDefinition struct {
	Key             Key             `json:"key"`
	Values          []string        `json:"values,omitempty"`
	Semantics       string          `json:"semantics"`
	DimensionPolicy DimensionPolicy `json:"dimension_policy"`
	ValueType       string          `json:"value_type,omitempty"`
}

// VocabularyAttributes is the shared key/value/semantics/dimension policy model.
func VocabularyAttributes() []AttributeDefinition {
	var out []AttributeDefinition
	add := func(k attributeKey, policy DimensionPolicy, semantics string, values ...string) {
		out = append(out, AttributeDefinition{Key: k.key(), Values: slices.Clone(values), Semantics: semantics, DimensionPolicy: policy})
	}
	add(ServiceNamespace, PolicyResource, "fixed product namespace", "tnl")
	add(ServiceName, PolicyResource, "process service, not a tenant or service", "tnld", "tnl", "tnl-accounts", "otel-collector")
	add(ServiceVersion, PolicyResource, "binary or deployed application version")
	add(ServiceInstanceID, PolicyResource, "unique runtime instance; random when unset, never a durable publisher identity")
	add(Environment, PolicyResource, "operator-declared deployment environment; omitted when unknown")
	add(RoleKey, PolicyResource, "configured process role", RoleControl.String(), RoleIngress.String(), RoleRelay.String(), RoleStandalone.String(), RolePublisher.String(), RoleClient.String(), RoleAccounts.String(), RoleCollector.String())
	for _, k := range []attributeKey{CloudProvider, CloudRegion, CloudAvailabilityZone} {
		add(k, PolicyResource, "known operator-declared cloud fact; no metadata discovery")
	}
	locations := []string{string(region.Local)}
	for _, location := range region.All() {
		locations = append(locations, string(location.Code))
	}
	add(RegionKey, PolicyTraceLog, "validated tnl location code; never a provider region or high-cardinality metric label", locations...)
	add(IngressRegion, PolicyBounded, "validated ingress location on an observed forwarding path", locations...)
	add(RelayRegion, PolicyBounded, "validated candidate relay location; a geographic hint, not proof of data-path cost", locations...)
	for _, k := range []attributeKey{TeamID, DeploymentID, ReplicaKey, PublisherGroupID, PublisherIdentityID, ServiceID, PublicURLID} {
		add(k, PolicyScoped, "authenticated stable identity; instrument allowlist required; service_id and public_url_id are mutually exclusive")
	}
	add(ServiceKindKey, PolicyScoped, "service or public URL; service wire value normalizes to service", Service.String(), PublicURL.String())
	add(Component, PolicyBounded, "component performing this work; independent of process role", "control", "authority", "private_ingress", "private_relay", "ingress", "relay", "publisher", "client", "accounts", "collector")
	add(ServiceProtocol, PolicyBounded, "service application protocol", "http", "postgres", "mysql", "tcp", "kubernetes")
	add(targetProvider, PolicyBounded, "publisher target discovery provider", "aws")
	add(targetType, PolicyBounded, "publisher target discovery resource type", "eks", "rds")
	add(targetDiscoveryOutcome, PolicyBounded, "publisher metadata refresh result", "success", "permission", "authentication", "not_found", "not_ready", "unavailable", "metadata", "changed")
	add(targetResourceARN, PolicyTraceLog, "validated cloud resource ARN; prohibited as a metric dimension")
	add(targetResourceID, PolicyTraceLog, "validated cloud resource identity; prohibited as a metric dimension")
	for _, k := range []attributeKey{KubernetesVerb, KubernetesAPIGroup, KubernetesResource, KubernetesSubresource} {
		add(k, PolicyTraceLog, "closed Kubernetes request classification; unknown groups/resources normalize to other; no namespace, object name, query, command, or payload")
	}
	for _, k := range []attributeKey{Transport, TransportPreference} {
		add(k, PolicyBounded, "selected transport (omit when not selected), or initial preference", "quic", "tls-tcp")
	}
	add(AccessPath, PolicyBounded, "visitor admission path", "connector", "direct")
	add(Exposure, PolicyBounded, "service reachability", "private", "public")
	add(TLSLeg, PolicyBounded, "TLS boundary owned by this observation", "visitor", "target")
	add(ConnectionSlot, PolicyBounded, "assigned publisher connection slot; omitted when unknown", "0", "1")
	add(Direction, PolicyBounded, "byte direction at the named component; wire bytes are distinct from target payload", "visitor_to_target", "target_to_visitor", "visitor_to_publisher", "publisher_to_visitor", "visitor_to_relay", "relay_to_visitor")
	add(Operation, PolicyBounded, "compiled operation name; never supplied input, SQL, or a path")
	out = append(out, AttributeDefinition{Key: MetricOverflow.key(), DimensionPolicy: PolicySDK, ValueType: "bool", Semantics: "SDK cardinality overflow point; only boolean true is valid; replaces all application dimensions and must survive collector filtering"})
	add(OutcomeKey, PolicyBounded, "operation result; domain detail belongs in reason, state, or event", Success.String(), Denied.String(), Rejected.String(), Timeout.String(), Canceled.String(), Error.String())
	add(Reason, PolicyBounded, "closed domain reason from semantic result classification or lifecycle observer; never error text", append(domainReasons(), "expected", "unexpected", "stale_assignment", "publisher_unavailable", "failed_ready")...)
	add(ErrorType, PolicyTraceLog, "exact owned failure.Reason, diagnostic code, or closed tunnel.<code>; unknown errors use "+string(failure.Unexpected), errorTypeValues()...)
	add(State, PolicyBounded, "closed per-instrument readiness or state-machine value")
	add(Event, PolicyBounded, "closed lifecycle event; bound is an SDK listener, registered is a native registration transition, and publication_ready is native routability; company reconciliation uses busy, completed, and partial_failed; status/watch readers do not emit transitions", events[1:]...)
	add(CertificateKind, PolicyBounded, "certificate worker domain", "public_url", "relay", "service", "control", "service_queue")
	add(DNSKind, PolicyBounded, "DNS worker domain", "authority", "public_url", "service", "public_url_challenge", "service_challenge", "relay_challenge")
	add(CleanupKind, PolicyBounded, "cleanup domain", "expired_publish_runs", "ephemeral_public_urls", "routing_floor", "routing_prune", "service_audit", "guest_private_state", "workloads", "native_peer_pairs", "relay_run_signing_keys")
	add(CapacityResource, PolicyBounded, "admission capacity domain", admissionResources...)
	add(HTTPMethod, PolicyBounded, "standard HTTP method; unknown methods normalize to _OTHER", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "_OTHER")
	add(HTTPStatus, PolicyBounded, "HTTP response status code, 100 through 599")
	add(HTTPRoute, PolicyBounded, "compiled matched route template only; never raw request path")
	add(TLSVersion, PolicyBounded, "negotiated TLS version", "1.2", "1.3")
	add(TLSResumed, PolicyBounded, "whether this TLS handshake resumed a session", "true", "false")
	add(ResponseOrigin, PolicyBounded, "component authoring the HTTP response", "tnl", "local_service")
	for _, k := range []attributeKey{VisitorConnectionID, RequestID, PublishRunID, PublishRunNumber, PublisherConnectionID, GrantID, ActorID, Revision, ImageHash, WorkloadSessionID, WorkloadRunID, WorkloadRunAttempt, WorkloadCheckRunID} {
		add(k, PolicyTraceLog, "high-churn correlation only; prohibited as a metric dimension")
	}
	for _, k := range []attributeKey{connectionClass, providerKey, publicURLPurpose, domainKind, certificatePlan, ingresspool, databasePurpose, signalKey} {
		add(k, PolicyBounded, "closed domain value supplied by the owning semantic observer")
	}
	slices.SortFunc(out, func(a, b AttributeDefinition) int { return strings.Compare(string(a.Key), string(b.Key)) })
	return out
}

func errorTypeValues() []string {
	var values []string
	for _, reason := range failure.Reasons() {
		values = append(values, string(reason))
	}
	for _, code := range diagnostic.Codes() {
		values = append(values, string(code))
	}
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.Unauthenticated, tunnelv1.InvalidMessage, tunnelv1.StalePublishRunNumber, tunnelv1.StaleConnectionAssignment, tunnelv1.DuplicatePublisherConnection, tunnelv1.DrainingPublisherConnection, tunnelv1.CapacityExceeded, tunnelv1.Unavailable, tunnelv1.Internal} {
		values = append(values, "tunnel."+string(code))
	}
	slices.Sort(values)
	return slices.Compact(values)
}

var admissionResources = []string{"client_hello_connections", "public_connections", "public_url_connections", "denied_connections", "denied_public_url_connections", "control_connections", "relay_tcp_connections", "publisher_connections", "relay_streams", "process_connection_rate", "source_connection_rate", "source_connections", "public_url_connection_rate", "public_url_connection_total", "pending_source_capacity", "pending_source_connections", "pending_public_url_connections", "pending_source_rate", "pending_public_url_rate", "traffic_keys", "traffic_bandwidth", "invalid_traffic_projection", "other"}

var attributeValues = func() map[Key][]string {
	out := make(map[Key][]string)
	for _, def := range VocabularyAttributes() {
		out[def.Key] = def.Values
	}
	return out
}()
