package stream

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type workloadControl struct {
	client    *workload.Client
	preferred []string
	subject   tunnelv1.VisitorSubject
	mu        sync.Mutex
	pairs     map[string]*workloadAssignmentPair
	owned     map[string]bool
	closed    bool
}

type workloadAssignmentPair struct {
	initialized bool
	pending     [2]*Assignment
	ingress     [2]string
	assigned    [2]string
	initialKey  string
	retry       [2]assignmentRetry
}

// NewWorkloadControl uses the exchanged workload's in-memory key. pass the
// result to Serve with Config.IdentityID empty. the caller owns Renew/Revoke;
// closing one service connector releases only that connector's assignments.
func NewWorkloadControl(client *workload.Client, preferred ...string) (Control, error) {
	if client == nil {
		return nil, ErrServiceConnection
	}
	subject, err := client.Subject()
	if err != nil {
		return nil, err
	}
	codes, err := region.Preferences(preferred)
	if err != nil {
		return nil, errors.Join(ErrServiceConnection, err)
	}
	selected := make([]string, len(codes))
	for index, code := range codes {
		selected[index] = string(code)
	}
	c := &workloadControl{client: client, preferred: selected, subject: subject, pairs: make(map[string]*workloadAssignmentPair), owned: make(map[string]bool)}
	return NewControlWithConfig(ControlConfig{Signer: c.signer, Assignment: c.assignment, Resolve: c.resolve, Release: c.release, Close: c.close, CloseContext: c.closeContext, PreparePeer: c.preparePeer})
}

func (c *workloadControl) signer(_ context.Context, identity string) (Signer, error) {
	s, err := c.client.Subject()
	if err != nil {
		return Signer{}, err
	}
	if identity != "" || s != c.subject {
		return Signer{}, ErrServiceConnection
	}
	return Signer{Subject: s, PublicKey: c.client.PublicKey(), Sign: c.client.Sign}, nil
}

func (c *workloadControl) assignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (Assignment, error) {
	if slot > 1 || subject != c.subject || !opaqueid.Valid(service, opaqueid.ServicePrefix) {
		return Assignment{}, ErrServiceConnection
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Assignment{}, ErrServiceConnection
	}
	for id, abandoned := range c.owned {
		if abandoned {
			if err := c.releaseLocked(ctx, id); err != nil {
				return Assignment{}, err
			}
		}
	}
	p := c.pairs[service]
	if p == nil {
		p = &workloadAssignmentPair{}
		c.pairs[service] = p
	}
	var response controlv1.WorkloadIngressAssignments
	var err error
	if !p.initialized {
		if p.initialKey == "" {
			p.initialKey, err = opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return Assignment{}, err
			}
		}
		response, err = c.client.CreateIngressAssignments(ctx, service, p.initialKey, c.preferred...)
		if err != nil {
			if errors.Is(err, clientcontrol.ErrStatusConflict) {
				p.initialKey = ""
			}
			return Assignment{}, err
		}
		p.initialized, p.initialKey = true, ""
		set, err := c.adopt(ctx, service, response, 2, "")
		if err != nil {
			return Assignment{}, err
		}
		sort.Slice(set, func(i, j int) bool { return set[i].IngressID < set[j].IngressID })
		p.pending[0], p.pending[1] = &set[0], &set[1]
	}
	if p.pending[slot] == nil {
		retry := &p.retry[slot]
		if retry.key == "" {
			retry.key, err = opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return Assignment{}, err
			}
			retry.exclude = p.ingress[1-slot]
			if a := p.pending[1-slot]; a != nil {
				retry.exclude = a.IngressID
			}
		}
		response, err = c.client.CreateIngressAssignment(ctx, service, retry.key, retry.exclude, c.preferred...)
		if err != nil {
			if errors.Is(err, clientcontrol.ErrStatusConflict) {
				*retry = assignmentRetry{}
			}
			return Assignment{}, err
		}
		exclude := retry.exclude
		*retry = assignmentRetry{}
		set, err := c.adopt(ctx, service, response, 1, exclude)
		if err != nil {
			return Assignment{}, err
		}
		p.pending[slot] = &set[0]
	}
	a := *p.pending[slot]
	p.pending[slot] = nil
	c.owned[a.SessionID] = true
	trust, err := c.client.IngressTransportTrust(ctx, a.SessionID)
	if err == nil && (trust.IngressId != a.IngressID || trust.TlsServerName != a.Endpoint.ServerName) {
		err = ErrServiceConnection
	}
	if err == nil {
		a.TransportTLS, err = clientcontrol.IngressTransportTLSConfig(trust)
	}
	if err != nil {
		return Assignment{}, errors.Join(err, c.releaseLocked(ctx, a.SessionID))
	}
	p.ingress[slot], p.assigned[slot] = a.IngressID, a.SessionID
	c.owned[a.SessionID] = false
	return a, nil
}

func (c *workloadControl) adopt(ctx context.Context, service string, response controlv1.WorkloadIngressAssignments, count int, exclude string) ([]Assignment, error) {
	session, err := c.client.Session()
	if err != nil {
		return nil, err
	}
	valid := visitorsubject.Equal(response.Subject, c.subject) && len(response.Assignments) == count
	set := make([]Assignment, 0, len(response.Assignments))
	seen := make(map[string]bool)
	for _, a := range response.Assignments {
		_, exists := c.owned[a.Id]
		if !exists && opaqueid.Valid(a.Id, opaqueid.ConnectorSessionPrefix) {
			c.owned[a.Id] = true
		}
		if exists || seen[a.IngressId] || a.IngressId == "" || a.IngressId == exclude || a.ServiceId != service || !opaqueid.Valid(a.Id, opaqueid.ConnectorSessionPrefix) || a.IngressAddress == "" || a.TlsServerName == "" || len(a.Credential) != 43 || !a.ExpiresAt.After(time.Now()) || a.ExpiresAt.After(session.ExpiresAt) {
			valid = false
		}
		seen[a.IngressId] = true
		set = append(set, Assignment{SessionID: a.Id, ServiceID: service, Subject: c.subject, IngressID: a.IngressId, Endpoint: muxsession.Endpoint{Address: a.IngressAddress, ServerName: a.TlsServerName}, Credential: a.Credential, ExpiresAt: a.ExpiresAt})
	}
	if !valid {
		err := ErrServiceConnection
		for id, abandoned := range c.owned {
			if abandoned {
				err = errors.Join(err, c.releaseLocked(ctx, id))
			}
		}
		return nil, err
	}
	for _, a := range set {
		c.owned[a.SessionID] = false
	}
	return set, nil
}

func (c *workloadControl) release(ctx context.Context, session string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.releaseLocked(ctx, session)
}
func (c *workloadControl) releaseLocked(ctx context.Context, session string) error {
	if _, exists := c.owned[session]; !exists {
		return nil
	}
	c.owned[session] = true
	finish, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.client.ReleaseIngressAssignment(finish, session); err != nil {
		return err
	}
	delete(c.owned, session)
	for _, p := range c.pairs {
		for slot := range 2 {
			if a := p.pending[slot]; a != nil && a.SessionID == session {
				p.pending[slot] = nil
			}
			if p.assigned[slot] == session {
				p.ingress[slot], p.assigned[slot] = "", ""
			}
		}
	}
	return nil
}
func (c *workloadControl) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.closeContext(ctx)
}
func (c *workloadControl) closeContext(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var err error
	for id := range c.owned {
		err = errors.Join(err, c.releaseLocked(ctx, id))
	}
	return err
}
func (c *workloadControl) resolve(ctx context.Context, service string) (Run, error) {
	r, err := c.client.SelectServiceRun(ctx, service)
	if err != nil {
		return Run{}, err
	}
	if r.ServiceId != service || !visitorsubject.Equal(r.Subject, c.subject) || !opaqueid.Valid(r.ServiceRunId, opaqueid.ServiceRunPrefix) || r.RunNumber < 1 || r.TrustRevision < 1 || !validProtocol(string(r.Protocol)) || !r.ExpiresAt.After(time.Now()) || r.Endpoint == nil {
		return Run{}, ErrServiceConnection
	}
	permission, err := c.client.PrepareVisitorToken(ctx, service)
	if err != nil {
		return Run{}, err
	}
	if r.PairReady != nil && !validPairHint(r.PairReady) {
		return Run{}, ErrServiceConnection
	}
	return Run{ServiceID: service, ServiceRunID: r.ServiceRunId, RunNumber: uint64(r.RunNumber), ValidUntil: r.ExpiresAt, Protocol: string(r.Protocol), TrustRevision: r.TrustRevision, Endpoint: r.Endpoint, Permission: permission, PairReady: clonePairHint(r.PairReady), Subject: c.subject}, nil
}

func (c *workloadControl) preparePeer(ctx context.Context, service string, subject tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	if subject != c.subject {
		return controlv1.NativePeerPair{}, ErrServiceConnection
	}
	return c.client.PrepareNativePeerPair(ctx, service, body)
}
