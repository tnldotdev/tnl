// package session composes in-memory deployment connector authority and sessions.
// native process owners and WASM adapters supply HTTP and relay transports; this
// owner has no filesystem, installed-process, listener or client-state dependency.
package session

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this supplies registered-key authority to the existing connector owner and
// peer-session engine. it owns neither listeners nor a second transport lifecycle.
type Deployment struct {
	request DeploymentOptions
	source  *auth.DeploymentTokenSource
	api     *clientcontrol.Client
}

func (*Deployment) String() string   { return "private deployment connector" }
func (*Deployment) GoString() string { return "private deployment connector" }

type DeploymentOptions struct {
	Credential string   `json:"credential"`
	Project    string   `json:"project"`
	Deployment string   `json:"deployment"`
	ControlURL string   `json:"controlUrl,omitempty"`
	Name       string   `json:"name,omitempty"`
	Services   []string `json:"services,omitempty"`
}

func (DeploymentOptions) String() string   { return "private deployment options" }
func (DeploymentOptions) GoString() string { return "private deployment options" }

func NewDeployment(request DeploymentOptions, httpClient *http.Client) (*Deployment, error) {
	if request.Deployment == "" {
		request.Deployment = request.Name
	}
	if request.Name != "" && request.Deployment != request.Name {
		return nil, auth.ErrDeploymentCredential
	}
	credential, err := auth.ParseDeploymentCredential(request.Credential)
	if err != nil {
		return nil, err
	}
	if err := credential.SelectProject(request.Project); err != nil {
		return nil, err
	}
	if request.Deployment == "local" || !(naming.ValidServiceName(request.Deployment) || opaqueid.Valid(request.Deployment, "dpl_")) || request.ControlURL != "" && request.ControlURL != credential.ControlURL {
		return nil, auth.ErrDeploymentCredential
	}
	if len(request.Services) > 32 {
		return nil, auth.ErrDeploymentCredential
	}
	request.Services = slices.Clone(request.Services)
	seen := map[string]bool{}
	for _, name := range request.Services {
		if credential.Approval.Permissions.Connect == nil {
			return nil, auth.ErrDeploymentCredential
		}
		if _, ok := (*credential.Approval.Permissions.Connect)[name]; !ok {
			return nil, auth.ErrDeploymentCredential
		}
		if !naming.ValidServiceName(name) || seen[name] {
			return nil, auth.ErrDeploymentCredential
		}
		seen[name] = true
	}
	source, err := auth.NewDeploymentTokenSource(credential, httpClient)
	if err != nil {
		return nil, err
	}
	api, err := clientcontrol.New(credential.ControlURL, httpClient, "")
	if err != nil {
		return nil, err
	}
	request.Credential = ""
	return &Deployment{request: request, source: source, api: api}, nil
}

func (d *Deployment) visitorSource(ctx context.Context) (controlv1.VisitorTokenSource, error) {
	token, err := d.source.Token(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(controlv1.VisitorTokenRegisteredKeySource{Kind: "registered_key", Credential: token})
}

func (d *Deployment) ServiceProtocol(name string) (controlv1.ServiceProtocol, error) {
	connect := d.source.Credential.Approval.Permissions.Connect
	if connect == nil {
		return "", connectorstream.ErrServiceConnection
	}
	protocol, permitted := (*connect)[name]
	if !permitted || !protocol.Valid() || !naming.ValidServiceName(name) || len(d.request.Services) > 0 && !slices.Contains(d.request.Services, name) {
		return "", connectorstream.ErrServiceConnection
	}
	return protocol, nil
}

func (d *Deployment) SelectRun(ctx context.Context, name string) (controlv1.ServiceSelection, error) {
	protocol, err := d.ServiceProtocol(name)
	if err != nil {
		return controlv1.ServiceSelection{}, err
	}
	source, err := d.visitorSource(ctx)
	if err != nil {
		return controlv1.ServiceSelection{}, err
	}
	a := d.source.Credential.Approval
	run, err := d.api.SelectDeploymentServiceRun(ctx, a.TeamId, a.ProjectKey, d.request.Deployment, name, source)
	if err != nil {
		return run, err
	}
	if !visitorsubject.Equal(run.Subject, d.source.Credential.Subject()) || !opaqueid.Valid(run.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(run.ServiceRunId, opaqueid.ServiceRunPrefix) || run.RunNumber < 1 || run.TrustRevision < 1 || run.Endpoint == nil || !run.ExpiresAt.After(time.Now()) || !run.Protocol.Valid() {
		return controlv1.ServiceSelection{}, connectorstream.ErrServiceConnection
	}
	if run.Protocol != protocol {
		return controlv1.ServiceSelection{}, connectorstream.ErrServiceConnection
	}
	return run, nil
}

func (d *Deployment) SelectService(ctx context.Context, name string) (controlv1.ServiceSummary, error) {
	run, err := d.SelectRun(ctx, name)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	return controlv1.ServiceSummary{Id: run.ServiceId, Name: name, TeamId: d.source.Credential.Approval.TeamId, Protocol: run.Protocol, TrustRevision: run.TrustRevision, Enabled: true, Endpoint: run.Endpoint, KubernetesAuth: run.KubernetesAuth}, nil
}

func (d *Deployment) ControlFor(name, service string) (connectorstream.Control, error) {
	credential := d.source.Credential
	captured, err := credential.CaptureSigner()
	if err != nil {
		return nil, err
	}
	public := captured.PublicKey()
	// resolve names only from the credential's fixed connect selection; control
	// resolves the exact saved binding again and fences ID replacement below.
	if credential.Approval.Permissions.Connect == nil {
		return nil, connectorstream.ErrServiceConnection
	}
	resolve := func(ctx context.Context, id string) (connectorstream.Run, error) {
		if id != service {
			return connectorstream.Run{}, connectorstream.ErrServiceConnection
		}
		if name == "" {
			return connectorstream.Run{}, connectorstream.ErrServiceConnection
		}
		r, err := d.SelectRun(ctx, name)
		if err != nil {
			return connectorstream.Run{}, err
		}
		if r.ServiceId != service {
			return connectorstream.Run{}, connectorstream.ErrServiceConnection
		}
		return connectorstream.Run{ServiceID: r.ServiceId, ServiceRunID: r.ServiceRunId, RunNumber: uint64(r.RunNumber), ValidUntil: r.ExpiresAt, Protocol: string(r.Protocol), TrustRevision: r.TrustRevision, Endpoint: r.Endpoint, PairReady: r.PairReady}, nil
	}
	validate := func(id string, subject controlv1.VisitorSubject) error {
		if id != service || !visitorsubject.Equal(subject, credential.Subject()) {
			return connectorstream.ErrServiceConnection
		}
		return nil
	}
	return connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
		Signer: func(_ context.Context, identity string) (connectorstream.Signer, error) {
			if identity != "" {
				return connectorstream.Signer{}, connectorstream.ErrServiceConnection
			}
			return connectorstream.Signer{Subject: credential.Subject(), PublicKey: public, Sign: captured.Sign}, nil
		},
		Resolve: resolve,
		Pair: func(ctx context.Context, id string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
			if err := validate(id, body.Subject); err != nil {
				return controlv1.ConnectorPeerPair{}, err
			}
			source, err := d.visitorSource(ctx)
			if err != nil {
				return controlv1.ConnectorPeerPair{}, err
			}
			body.Source = source
			return d.api.PrepareSourceConnectorPeerPair(ctx, id, body)
		},
		RenewPair: func(ctx context.Context, id string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
			if err := validate(id, body.Subject); err != nil {
				return controlv1.ConnectorPeerPairRenewal{}, err
			}
			if body.PreviousPairId == nil || body.Action != "renew" {
				return controlv1.ConnectorPeerPairRenewal{}, connectorstream.ErrServiceConnection
			}
			source, err := d.visitorSource(ctx)
			if err != nil {
				return controlv1.ConnectorPeerPairRenewal{}, err
			}
			body.Source = source
			return d.api.RenewSourceConnectorPeerPair(ctx, id, *body.PreviousPairId, body)
		},
		RebindPair: func(ctx context.Context, id, pair string, body controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
			if err := validate(id, body.Subject); err != nil {
				return controlv1.ConnectorPeerPairRebindState{}, err
			}
			source, err := d.visitorSource(ctx)
			if err != nil {
				return controlv1.ConnectorPeerPairRebindState{}, err
			}
			body.Source = source
			return d.api.RebindSourceConnectorPeerPair(ctx, id, pair, body)
		},
		RetirePair: d.api.RetireConnectorPeerPair,
		Permission: func(ctx context.Context, id string) (controlv1.VisitorTokenResponse, error) {
			if id != service {
				return controlv1.VisitorTokenResponse{}, connectorstream.ErrServiceConnection
			}
			source, err := d.visitorSource(ctx)
			if err != nil {
				return controlv1.VisitorTokenResponse{}, err
			}
			return d.api.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: id}, Source: source})
		},
		Close: func(context.Context) error { return nil },
	})
}

func (d *Deployment) Refresh(ctx context.Context) error {
	_, err := d.source.Token(ctx)
	return err
}

func (d *Deployment) ExpiresAt() time.Time { return d.source.Credential.Approval.ExpiresAt }
