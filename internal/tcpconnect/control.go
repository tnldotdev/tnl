package tcpconnect

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type controlAdapter struct {
	client     *controlclient.Client
	profile    *clientstate.Store
	identityID string
	deviceMu   sync.Mutex
	mu         sync.Mutex
	pairs      map[assignmentKey]*assignmentPair
	// true marks an abandoned reservation whose release must be retried;
	// false marks a pending token or a path that still owns its assignment.
	owned  map[string]bool
	closed bool
}

type assignmentKey struct{ service, device string }

type assignmentPair struct {
	initialized bool
	pending     [2]*controlv1.PrivateConnectorSessionSetup
	ingress     [2]string
	assigned    [2]string
	initialKey  string
	renewal     [2]assignmentRetry
}

type assignmentRetry struct{ key, exclude string }

func (*controlAdapter) String() string   { return "private connector control" }
func (*controlAdapter) GoString() string { return "private connector control" }

// NewControl uses the signed-in identity's protected, server-scoped device key.
// construction does not enroll or replace a key; enrollment is retryable using
// the key durably saved before its first HTTP request.
func NewControl(client *controlclient.Client, profile *clientstate.Store, identityID string) (Control, error) {
	if client == nil || profile == nil || !opaqueid.Valid(identityID, opaqueid.IdentityPrefix) {
		return nil, ErrPrivateConnection
	}
	return &controlAdapter{client: client, profile: profile, identityID: identityID, pairs: make(map[assignmentKey]*assignmentPair), owned: make(map[string]bool)}, nil
}

func (c *controlAdapter) PrivateConnectorSigner(ctx context.Context, identity string) (Signer, error) {
	if identity != c.identityID {
		return Signer{}, ErrPrivateConnection
	}
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	device, err := c.profile.EnsureEnrolledVisitorDevice(ctx, identity, c.client.EnrollVisitorDevice)
	if err != nil {
		if errors.Is(err, clientstate.ErrPublisherStateConflict) {
			return Signer{}, errors.Join(ErrPrivateConnection, err)
		}
		return Signer{}, err
	}
	return Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device.ID}, PublicKey: device.SigningKey.Public().(ed25519.PublicKey), Sign: func(digest []byte) []byte { return ed25519.Sign(device.SigningKey, digest) }}, nil
}

func (c *controlAdapter) PrivateConnectorAssignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (Assignment, error) {
	if slot > 1 || !opaqueid.Valid(service, opaqueid.PrivateServicePrefix) {
		return Assignment{}, ErrPrivateConnection
	}
	local, err := c.PrivateConnectorSigner(ctx, c.identityID)
	if err != nil {
		return Assignment{}, err
	}
	if subject != local.Subject {
		return Assignment{}, ErrPrivateConnection
	}
	device := subject.DeviceID
	// serialize assignment allocation and consumption, including failures fetching
	// trust. an attempted token is never handed out a second time, and renewing
	// one slot never releases its sibling's bound session.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Assignment{}, ErrPrivateConnection
	}
	// failed releases stay owned and must be retried before reserving more
	// capacity. a canceled caller cannot abandon its cleanup request.
	if err := c.releaseAbandonedLocked(ctx); err != nil {
		return Assignment{}, err
	}
	key := assignmentKey{service: service, device: device}
	pair := c.pairs[key]
	if pair == nil {
		pair = &assignmentPair{}
		c.pairs[key] = pair
	}
	for i, pending := range pair.pending {
		if pending != nil && !pending.ExpiresAt.After(time.Now()) {
			pair.pending[i] = nil
			if err := c.releaseLocked(ctx, pending.ConnectorSessionId); err != nil {
				return Assignment{}, err
			}
		}
	}
	if !pair.initialized {
		if pair.initialKey == "" {
			pair.initialKey, err = opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return Assignment{}, err
			}
		}
		setups, err := c.client.CreateVisitorIngressAssignments(ctx, service, device, pair.initialKey)
		if err != nil {
			if errors.Is(err, controlclient.ErrNotFound) {
				pair.initialKey = ""
			}
			return Assignment{}, err
		}
		pair.initialized = true
		pair.initialKey = ""
		if err := c.adoptAssignmentsLocked(ctx, service, device, setups); err != nil {
			return Assignment{}, err
		}
		if len(setups) != 2 || setups[0].IngressId == setups[1].IngressId || setups[0].ConnectorSessionId == setups[1].ConnectorSessionId {
			return Assignment{}, errors.Join(ErrPrivateConnection, c.releaseAbandonedLocked(ctx))
		}
		sort.Slice(setups, func(i, j int) bool { return setups[i].IngressId < setups[j].IngressId })
		for i := range setups {
			pair.pending[i] = &setups[i]
			c.owned[setups[i].ConnectorSessionId] = false
		}
	}
	if pair.pending[slot] == nil {
		// startup reserves a pair once. every refresh reserves only this slot,
		// so a full healthy sibling cannot block recovery or consume capacity.
		retry := &pair.renewal[slot]
		if retry.key == "" {
			retry.key, err = opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return Assignment{}, err
			}
			retry.exclude = pair.ingress[1-slot]
			if pending := pair.pending[1-slot]; pending != nil {
				retry.exclude = pending.IngressId
			}
		}
		setup, err := c.client.CreateVisitorIngressAssignment(ctx, service, device, retry.exclude, retry.key)
		if err != nil {
			if errors.Is(err, controlclient.ErrNotFound) {
				*retry = assignmentRetry{}
			}
			return Assignment{}, err
		}
		exclude := retry.exclude
		*retry = assignmentRetry{}
		if err := c.adoptAssignmentsLocked(ctx, service, device, []controlv1.PrivateConnectorSessionSetup{setup}); err != nil {
			return Assignment{}, err
		}
		if setup.IngressId == exclude {
			return Assignment{}, errors.Join(ErrPrivateConnection, c.releaseLocked(ctx, setup.ConnectorSessionId))
		}
		pair.pending[slot] = &setup
		c.owned[setup.ConnectorSessionId] = false
	}
	a := *pair.pending[slot]
	pair.pending[slot] = nil
	c.owned[a.ConnectorSessionId] = true
	if a.IngressId == pair.ingress[1-slot] {
		return Assignment{}, errors.Join(ErrPrivateConnection, c.releaseLocked(ctx, a.ConnectorSessionId))
	}
	trust, err := c.client.GetVisitorIngressTransportTrust(ctx, a.ConnectorSessionId)
	if err != nil {
		return Assignment{}, errors.Join(err, c.releaseLocked(ctx, a.ConnectorSessionId))
	}
	if trust.IngressId != a.IngressId || trust.TlsServerName != a.TlsServerName {
		return Assignment{}, errors.Join(ErrPrivateConnection, c.releaseLocked(ctx, a.ConnectorSessionId))
	}
	verification, err := controlclient.IngressTransportTLSConfig(trust)
	if err != nil {
		return Assignment{}, errors.Join(err, c.releaseLocked(ctx, a.ConnectorSessionId))
	}
	pair.ingress[slot], pair.assigned[slot] = a.IngressId, a.ConnectorSessionId
	c.owned[a.ConnectorSessionId] = false
	return Assignment{SessionID: a.ConnectorSessionId, PrivateServiceID: a.PrivateServiceId, Subject: subject,
		IngressID: a.IngressId, Endpoint: muxsession.Endpoint{Address: a.IngressAddress, ServerName: a.TlsServerName},
		Credential: a.SessionCredential, ExpiresAt: a.ExpiresAt, TransportTLS: verification}, nil
}

// adoptAssignmentsLocked records new reservations before validating the response
// so malformed or unused setups can be released immediately. a repeated session
// ID cannot transfer ownership away from an existing healthy path.
func (c *controlAdapter) adoptAssignmentsLocked(ctx context.Context, service, device string, setups []controlv1.PrivateConnectorSessionSetup) error {
	valid := true
	for _, a := range setups {
		_, existing := c.owned[a.ConnectorSessionId]
		if !existing && opaqueid.Valid(a.ConnectorSessionId, opaqueid.PrivateConnectorSessionPrefix) {
			c.owned[a.ConnectorSessionId] = true
		}
		if existing || a.PrivateServiceId != service || !visitorsubject.Equal(a.Subject, tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: c.identityID}) ||
			!opaqueid.Valid(a.ConnectorSessionId, opaqueid.PrivateConnectorSessionPrefix) || a.IngressId == "" || a.IngressAddress == "" ||
			a.TlsServerName == "" || a.SessionCredential == "" || !a.ExpiresAt.After(time.Now()) {
			valid = false
		}
	}
	if !valid {
		return errors.Join(ErrPrivateConnection, c.releaseAbandonedLocked(ctx))
	}
	return nil
}

func (c *controlAdapter) releaseAbandonedLocked(ctx context.Context) error {
	var result error
	for id, abandoned := range c.owned {
		if abandoned {
			result = errors.Join(result, c.releaseLocked(ctx, id))
		}
	}
	return result
}

// ReleasePrivateConnectorAssignment retires exactly one attempted or closed
// path. a healthy sibling remains owned until its own path closes.
func (c *controlAdapter) ReleasePrivateConnectorAssignment(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.releaseLocked(ctx, id)
}

func (c *controlAdapter) releaseLocked(ctx context.Context, id string) error {
	if _, found := c.owned[id]; !found {
		return nil
	}
	c.owned[id] = true
	finish, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.client.ReleaseVisitorIngressAssignment(finish, id); err != nil {
		return err
	}
	delete(c.owned, id)
	for _, pair := range c.pairs {
		for slot := range uint8(2) {
			if pending := pair.pending[slot]; pending != nil && pending.ConnectorSessionId == id {
				pair.pending[slot] = nil
			}
			if pair.assigned[slot] == id {
				pair.assigned[slot], pair.ingress[slot] = "", ""
			}
		}
	}
	return nil
}

func (c *controlAdapter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CloseContext(ctx)
}

func (c *controlAdapter) CloseContext(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var result error
	for id := range c.owned {
		result = errors.Join(result, c.releaseLocked(ctx, id))
	}
	return result
}

func (c *controlAdapter) ResolvePrivateService(ctx context.Context, service string) (Run, error) {
	if !opaqueid.Valid(service, opaqueid.PrivateServicePrefix) {
		return Run{}, ErrPrivateConnection
	}
	signer, err := c.PrivateConnectorSigner(ctx, c.identityID)
	if err != nil {
		return Run{}, err
	}
	selected, err := c.client.SelectPrivateServiceRun(ctx, service, signer.Subject.DeviceID)
	if err != nil {
		return Run{}, err
	}
	if selected.ManagedTls == nil ||
		selected.PrivateServiceId != service || !visitorsubject.Equal(selected.Subject, signer.Subject) ||
		!opaqueid.Valid(selected.PrivateRunId, opaqueid.PrivateRunPrefix) || selected.RunNumber < 1 || selected.TrustRevision < 1 ||
		!selected.ExpiresAt.After(time.Now()) || !validProtocol(string(selected.Protocol)) {
		return Run{}, ErrPrivateConnection
	}
	return Run{PrivateServiceID: service, PrivateRunID: selected.PrivateRunId, RunNumber: uint64(selected.RunNumber),
		ValidUntil: selected.ExpiresAt, Protocol: string(selected.Protocol), TrustRevision: selected.TrustRevision, ManagedTLS: selected.ManagedTls}, nil
}
