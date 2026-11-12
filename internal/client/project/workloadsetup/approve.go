package workloadsetup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ApprovalAuthority interface {
	GetWorkloadApproval(context.Context, string, string) (authorityv1.WorkloadApproval, error)
	ApproveWorkload(context.Context, string, string, authorityv1.WorkloadApprovalRequest) (authorityv1.WorkloadApproval, error)
}

type ApprovalEnvironments interface {
	ListEnvironments(context.Context, string, string) ([]controlv1.Environment, error)
}

type ApprovalOptions struct {
	Project                                       clientproject.Project
	Server, TeamID, Environment, Workload, Intent string
	ExpiresAt                                     time.Time
}

// approve is separate from apply. the server is the journal: recover an exact
// receipt before resolving provider names or creating any new permission.
func Approve(ctx context.Context, authority ApprovalAuthority, environments ApprovalEnvironments, options ApprovalOptions) (authorityv1.WorkloadApproval, error) {
	return approve(ctx, authority, environments, options, Resolve)
}

func approve(ctx context.Context, authority ApprovalAuthority, environments ApprovalEnvironments, o ApprovalOptions, bind func(context.Context, Options) (map[string]controlv1.ProjectWorkload, error)) (authorityv1.WorkloadApproval, error) {
	var zero authorityv1.WorkloadApproval
	declared := o.Project.Config
	if o.Project.Declared != nil {
		declared = *o.Project.Declared
	}
	environment, found := declared.Environments[o.Environment]
	if !found || o.Environment == "local" {
		return zero, errors.New("--environment must select a declared remote environment")
	}
	workload, found := environment.Workloads[o.Workload]
	if !found {
		return zero, errors.New("--workload must select a workload declared in this environment")
	}
	if o.Intent == "" || o.ExpiresAt.IsZero() {
		return zero, errors.New("approval requires --intent and an absolute --expires-at; reuse both values to recover a lost reply")
	}
	if err := config.ValidateWorkloads(declared.Services, map[string]config.Workload{o.Workload: workload}); err != nil {
		return zero, err
	}
	source, err := o.Project.SourceIdentity(ctx)
	if err != nil {
		return zero, err
	}
	protocols := make(map[string]controlv1.ServiceProtocol, len(workload.Services))
	for _, name := range workload.Services {
		protocols[name] = controlv1.ServiceProtocol(config.Protocol(declared.Services[name]))
	}
	intent, err := json.Marshal(struct {
		Server, Team, Project, Environment, Workload string
		Declaration                                  config.Workload
		Protocols                                    map[string]controlv1.ServiceProtocol
	}{o.Server, o.TeamID, source.Key, o.Environment, o.Workload, workload, protocols})
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(intent)
	hash := hex.EncodeToString(digest[:])
	previous, err := authority.GetWorkloadApproval(ctx, o.TeamID, o.Intent)
	if err == nil {
		if !validApproval(previous, o, source.Key, hash, protocols, int(workload.DurationLimit()/time.Second)) {
			return zero, invalidApproval()
		}
		return previous, nil
	}
	if !errors.Is(err, clientauthority.ErrNotFound) {
		return zero, err
	}
	inventory, err := environments.ListEnvironments(ctx, o.TeamID, source.Key)
	if err != nil {
		return zero, err
	}
	selected, err := resolve.SelectEnvironments(inventory, o.TeamID, source.Key, o.Environment)
	if err != nil {
		return zero, err
	}
	// inventory exposes active environments; approval rechecks retirement and
	// the exact mutation revision inside its authority transaction.
	if len(selected) != 1 {
		return zero, errors.New("apply the selected environment before approving a workload")
	}
	saved := selected[0]
	for name, protocol := range protocols {
		matches := 0
		for _, service := range saved.Services {
			if service.Service == name && service.Protocol == protocol {
				matches++
			}
		}
		if matches != 1 {
			return zero, errors.New("apply the declared service protocols to this environment before approving its workload")
		}
	}
	bindings, err := bind(ctx, Options{Directory: o.Project.Root, Server: o.Server, Workloads: map[string]config.Workload{o.Workload: workload}, Repository: o.Project.GitHubRepository})
	if err != nil {
		return zero, err
	}
	trust, err := approvalTrust(bindings[o.Workload], workload.TokenAudience(o.Server))
	if err != nil {
		return zero, err
	}
	services := slices.Clone(workload.Services)
	slices.Sort(services)
	request := authorityv1.WorkloadApprovalRequest{ProjectKey: source.Key, EnvironmentId: saved.Id, ExpectedRevision: saved.MutationRevision, Workload: o.Workload, IntentHash: hash, Trust: trust, Services: services, MaxDurationSeconds: int(workload.DurationLimit() / time.Second), ExpiresAt: o.ExpiresAt.UTC()}
	result, err := authority.ApproveWorkload(ctx, o.TeamID, o.Intent, request)
	if err != nil {
		return zero, err
	}
	if !validApproval(result, o, source.Key, hash, protocols, request.MaxDurationSeconds) || !reflect.DeepEqual(result.Request, request) {
		return zero, invalidApproval()
	}
	return result, nil
}

func validApproval(a authorityv1.WorkloadApproval, o ApprovalOptions, project, hash string, protocols map[string]controlv1.ServiceProtocol, duration int) bool {
	r := a.Request
	return a.IntentKey == o.Intent && r.ProjectKey == project && r.IntentHash == hash && r.Workload == o.Workload && r.ExpiresAt.Equal(o.ExpiresAt) && r.ExpectedRevision > 0 && !a.CreatedAt.IsZero() && r.MaxDurationSeconds == duration && slices.Equal(r.Services, slices.Sorted(maps.Keys(protocols))) &&
		opaqueid.Valid(r.EnvironmentId, opaqueid.EnvironmentPrefix) && opaqueid.Valid(a.Machine.Id, "mci_") && a.Machine.TeamId == o.TeamID && a.Machine.ProofKind == "oidc" && a.Machine.Revision > 0 && a.Machine.Trust != nil && sameApprovalTrust(*a.Machine.Trust, r.Trust) &&
		opaqueid.Valid(a.Selection.PermissionId, "mwp_") && a.Selection.Environment.Server == o.Server && a.Selection.Environment.ProjectKey == project && a.Selection.Environment.EnvironmentId == r.EnvironmentId && reflect.DeepEqual(a.Selection.Services, protocols)
}

func sameApprovalTrust(a, b authorityv1.MachineTrust) bool {
	// validated event lists are sets. ignore only their order, without changing
	// the saved receipt or relaxing any other registered-machine trust field.
	normalize := func(trust authorityv1.MachineTrust) authorityv1.MachineTrust {
		if trust.Events != nil {
			events := slices.Clone(*trust.Events)
			slices.Sort(events)
			trust.Events = &events
		}
		return trust
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

func invalidApproval() error {
	return failure.Wrap("read workload approval", failure.ServerResponseInvalid, errors.New("approval intent differs from this workload or returned another identity or environment; inspect the original intent, or use a new explicit intent"))
}

// provider metadata resolution is not an authority model. convert its exact
// stable facts into the registered-machine contract used by real admission.
func approvalTrust(bound controlv1.ProjectWorkload, audience string) (authorityv1.MachineTrust, error) {
	t := bound.Trust
	trust := authorityv1.MachineTrust{Provider: authorityv1.MachineTrustProvider(t.Provider), Issuer: t.Issuer, JwksUrl: t.JwksUrl, Audience: t.Audience, Claims: t.Claims}
	if bound.Provider == controlv1.WorkloadGitHub {
		g := bound.Github
		if g == nil {
			return trust, ErrBinding
		}
		events := slices.Clone(g.Events)
		slices.Sort(events)
		trust = authorityv1.MachineTrust{Provider: authorityv1.MachineTrustGitHub, Issuer: "https://token.actions.githubusercontent.com", JwksUrl: "https://token.actions.githubusercontent.com/.well-known/jwks", Audience: audience, Claims: map[string]string{"repository": g.Repository, "repository_id": g.RepositoryId, "repository_owner_id": g.RepositoryOwnerId, "workflow_ref": g.WorkflowRef, "ref": g.Ref}, Events: &events}
		if g.Environment != nil {
			trust.Claims["environment"] = *g.Environment
		}
		if g.JobWorkflowRef != nil {
			trust.Claims["job_workflow_ref"] = *g.JobWorkflowRef
		}
	}
	if trust.Provider == "" || trust.Issuer == "" || trust.JwksUrl == "" || trust.Audience == "" || len(trust.Claims) == 0 {
		return trust, ErrBinding
	}
	if string(trust.Provider) != string(bound.Provider) {
		return trust, ErrBinding
	}
	return trust, nil
}
