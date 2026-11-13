package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func connectionDeployment(options ContextOptions) (projectConfiguration, connectorruntime.Context, error) {
	r := options.Deployment
	credential, err := auth.ParseDeploymentCredential(r.Token)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	if credential.SelectProject(r.Project) != nil || options.Manifest != "" || options.Workload != "" ||
		r.Name == "local" || !(naming.ValidServiceName(r.Name) || opaqueid.Valid(r.Name, "pgrp_")) || options.TeamID != "" && options.TeamID != credential.Approval.TeamId {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
	}
	if credential.Approval.Permissions.Connect == nil {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrUnauthorized
	}
	protocols := *credential.Approval.Permissions.Connect
	names := slices.Clone(r.Services)
	if len(names) == 0 {
		for name := range protocols {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	configuration := config.TNL{Services: config.Services{}}
	for i, name := range names {
		protocol, ok := protocols[name]
		if !ok || !naming.ValidServiceName(name) || !protocol.Valid() || i > 0 && names[i-1] == name {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrUnauthorized
		}
		configuration.Services[name] = config.Service{Protocol: new(string(protocol)), PublisherGroup: new(r.Name)}
	}
	directory, err := filepath.Abs(options.Directory)
	if err == nil {
		directory, err = filepath.EvalSymlinks(directory)
	}
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	public, err := credential.PublicKey()
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	encoded, err := json.Marshal([]any{credential.ControlURL, credential.Approval, public, names, r.Name})
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	digest := sha256.Sum256(encoded)
	id := hex.EncodeToString(digest[:])
	scope := connectorruntime.Context{Schema: 1, Directory: directory, ConfigDigest: id, Server: credential.ControlURL, Audience: credential.ControlURL, TeamID: credential.Approval.TeamId, ProjectKey: credential.Approval.ProjectKey, ProjectLabel: credential.Approval.ProjectKey, SourceID: id, WorktreeKey: "deployment", Deployment: r.Name, Services: names}
	project := projectConfiguration{Project: clientproject.Project{Root: directory, Config: configuration, Deployment: r.Name}}
	return project, scope, scope.Validate()
}

// this supplies registered-key authority to the existing connector owner and
// peer-session engine. it owns neither listeners nor a second transport lifecycle.
type deploymentConnection struct {
	request connectorruntime.DeploymentRequest
	source  *auth.DeploymentTokenSource
	api     *clientcontrol.Client
}

func (*deploymentConnection) String() string   { return "private deployment connector" }
func (*deploymentConnection) GoString() string { return "private deployment connector" }

func newDeploymentConnection(request connectorruntime.DeploymentRequest, httpClient *http.Client) (*deploymentConnection, error) {
	credential, err := auth.ParseDeploymentCredential(request.Token)
	if err != nil {
		return nil, err
	}
	if err := credential.SelectProject(request.Project); err != nil {
		return nil, err
	}
	source, err := auth.NewDeploymentTokenSource(credential, httpClient)
	if err != nil {
		return nil, err
	}
	api, err := clientcontrol.New(credential.ControlURL, httpClient, "")
	if err != nil {
		return nil, err
	}
	request.Token = ""
	return &deploymentConnection{request: request, source: source, api: api}, nil
}

func (d *deploymentConnection) visitorSource(ctx context.Context) (controlv1.VisitorTokenSource, error) {
	token, err := d.source.Token(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(controlv1.VisitorTokenRegisteredKeySource{Kind: "registered_key", Credential: token})
}

func (d *deploymentConnection) selectRun(ctx context.Context, name string) (controlv1.ServiceSelection, error) {
	source, err := d.visitorSource(ctx)
	if err != nil {
		return controlv1.ServiceSelection{}, err
	}
	a := d.source.Credential.Approval
	run, err := d.api.SelectDeploymentServiceRun(ctx, a.TeamId, a.ProjectKey, d.request.Name, name, source)
	if err != nil {
		return run, err
	}
	if !visitorsubject.Equal(run.Subject, d.source.Credential.Subject()) || !opaqueid.Valid(run.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(run.ServiceRunId, opaqueid.ServiceRunPrefix) || run.RunNumber < 1 || run.TrustRevision < 1 || run.Endpoint == nil || !run.ExpiresAt.After(time.Now()) || !run.Protocol.Valid() {
		return controlv1.ServiceSelection{}, connectorruntime.ErrInvalid
	}
	return run, nil
}

func (d *deploymentConnection) selectService(ctx context.Context, name string) (controlv1.Service, error) {
	run, err := d.selectRun(ctx, name)
	if err != nil {
		return controlv1.Service{}, err
	}
	return controlv1.Service{Id: run.ServiceId, Name: name, TeamId: d.source.Credential.Approval.TeamId, Protocol: run.Protocol, Enabled: true, Endpoint: run.Endpoint, KubernetesAuth: run.KubernetesAuth}, nil
}

func (d *deploymentConnection) controlFor(name, service string) (connectorstream.Control, error) {
	credential := d.source.Credential
	public, err := credential.PublicKey()
	if err != nil {
		return nil, err
	}
	// resolve names only from the credential's fixed connect selection; control
	// resolves the exact saved binding again and fences ID replacement below.
	if credential.Approval.Permissions.Connect == nil {
		return nil, connectorruntime.ErrUnauthorized
	}
	resolve := func(ctx context.Context, id string) (connectorstream.Run, error) {
		if id != service {
			return connectorstream.Run{}, connectorruntime.ErrUnauthorized
		}
		if name == "" {
			return connectorstream.Run{}, connectorruntime.ErrUnauthorized
		}
		r, err := d.selectRun(ctx, name)
		if err != nil {
			return connectorstream.Run{}, err
		}
		if r.ServiceId != service {
			return connectorstream.Run{}, connectorruntime.ErrUnauthorized
		}
		return connectorstream.Run{ServiceID: r.ServiceId, ServiceRunID: r.ServiceRunId, RunNumber: uint64(r.RunNumber), ValidUntil: r.ExpiresAt, Protocol: string(r.Protocol), TrustRevision: r.TrustRevision, Endpoint: r.Endpoint, PairReady: r.PairReady}, nil
	}
	validate := func(id string, subject controlv1.VisitorSubject) error {
		if id != service || !visitorsubject.Equal(subject, credential.Subject()) {
			return connectorruntime.ErrUnauthorized
		}
		return nil
	}
	return connectorstream.NewControlWithConfig(connectorstream.ControlConfig{
		Signer: func(_ context.Context, identity string) (connectorstream.Signer, error) {
			if identity != "" {
				return connectorstream.Signer{}, connectorruntime.ErrUnauthorized
			}
			return connectorstream.Signer{Subject: credential.Subject(), PublicKey: public, Sign: func(message []byte) []byte { value, _ := credential.Sign(message); return value }}, nil
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
				return controlv1.ConnectorPeerPairRenewal{}, connectorruntime.ErrInvalid
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
		Permission: func(ctx context.Context, id string) (controlv1.VisitorTokenResponse, error) {
			if id != service {
				return controlv1.VisitorTokenResponse{}, connectorruntime.ErrUnauthorized
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
