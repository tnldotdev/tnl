package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// enrolledControl uses only the grant selected by the one-use enrollment key.
// run tokens continue to authorize the normal publisher lifecycle afterwards.
type enrolledControl struct {
	*controlclient.Client
	authority *authorityclient.Client
	private   ed25519.PrivateKey
	identity  authorityv1.PublisherEnrollmentResult
	route     controlv1.PublicURL
}

var _ publisher.PublicURLControlClient = (*enrolledControl)(nil)

func (c *enrolledControl) access(ctx context.Context) (string, error) {
	return c.authority.ExchangePublisherAssertion(ctx, c.identity.ClientId, c.identity.GrantId, c.identity.KeyId, c.private)
}

func (c *enrolledControl) GetPublicURLByHostname(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	if c.route.Id != "" {
		if c.route.TeamId != teamID || c.route.CanonicalHostname != hostname {
			return controlv1.PublicURL{}, controlclient.ErrNotFound
		}
		return c.route, nil
	}
	token, err := c.access(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	route, err := c.Client.PublisherPublicURL(ctx, token)
	if err != nil {
		return route, err
	}
	if c.identity.PublicUrlId == nil || route.Id != *c.identity.PublicUrlId || route.TeamId != teamID || route.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, controlclient.ErrNotFound
	}
	return route, nil
}

func (c *enrolledControl) CreatePublishRun(ctx context.Context, id, key string) (controlv1.PublishRunSetup, error) {
	return c.CreatePublishRunWithTraffic(ctx, id, key, trafficlimits.Selection{})
}

func (c *enrolledControl) CreatePublishRunWithTraffic(ctx context.Context, id, key string, traffic trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	if c.route.Id != "" && id != c.route.Id || c.identity.PublicUrlId != nil && id != *c.identity.PublicUrlId {
		return controlv1.PublishRunSetup{}, controlclient.ErrNotFound
	}
	token, err := c.access(ctx)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	proof, err := publisheridentity.SignRun(c.private, id, key)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	return c.Client.CreatePublisherRun(ctx, id, key, token, proof, traffic)
}

func (*enrolledControl) CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (*enrolledControl) UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (c *enrolledControl) DeletePublicURL(ctx context.Context, id string) error {
	if c.identity.Kind != "namespace" || id != c.route.Id {
		return controlclient.ErrStatusConflict
	}
	token, err := c.access(ctx)
	if err != nil {
		return err
	}
	return c.Client.DeletePublisherPublicURL(ctx, token, id)
}

func enrollmentKeyInput(value string, input io.Reader) (string, error) {
	if value == "-" {
		read, err := io.ReadAll(io.LimitReader(input, 257))
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(read))
	}
	if value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\r\n") {
		return "", failure.Wrap("read publisher enrollment key", failure.InvalidTunnelFlags,
			errors.New("pass one enrollment key or --enroll-key - to read stdin"))
	}
	return value, nil
}

func runEnrolledPublish(ctx context.Context, flags publishCommand, output *publishOutput, telemetry telemetryReporter, input io.Reader) (result error) {
	if flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" {
		return failure.Wrap("validate enrollment options", failure.InvalidTunnelFlags, errors.New("the enrollment key selects the public URL scope"))
	}
	if flags.AllowAllIPs && len(flags.AllowIP) != 0 {
		return failure.Wrap("validate visitor IP policy", failure.InvalidTunnelFlags, errors.New("select --allow-all-ips or --allow-ip"))
	}
	key, err := enrollmentKeyInput(flags.EnrollKey, input)
	if err != nil {
		return err
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	client, err := controlclient.New(server, nil, "")
	if err != nil {
		return err
	}
	authority, err := authorityclient.New(server, nil, "")
	if err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity, err := authority.RedeemPublisherEnrollment(ctx, key, public)
	if err != nil {
		return err
	}
	if !opaqueid.Valid(identity.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		!opaqueid.Valid(identity.GrantId, opaqueid.PublisherGrantPrefix) {
		return failure.Wrap("validate enrollment", failure.ServerResponseInvalid, errors.New("control returned an invalid publisher identity"))
	}
	control := &enrolledControl{Client: client, authority: authority, private: private, identity: identity}
	var route controlv1.PublicURL
	if identity.PublicUrlId != nil && identity.Kind == "saved_url" {
		if flags.Ephemeral || len(flags.AllowIP) != 0 || flags.AllowAllIPs {
			return failure.Wrap("validate saved URL", failure.InvalidTunnelFlags, errors.New("visitor policy and lifecycle are set on the saved URL"))
		}
		token, err := control.access(ctx)
		if err != nil {
			return err
		}
		route, err = client.PublisherPublicURL(ctx, token)
		if err != nil {
			return err
		}
		if route.Id != *identity.PublicUrlId || route.TeamId != identity.TeamId || route.Ephemeral {
			return controlclient.ErrNotFound
		}
	} else if identity.Namespace != nil && identity.Kind == "namespace" {
		if flags.Protocol != "" && flags.Protocol != "http" || flags.TargetTLS || flags.TargetTLSName != "" || flags.TargetCAFile != "" {
			return failure.Wrap("validate namespace target", failure.InvalidTunnelFlags, errors.New("namespace publishing requires an HTTP target"))
		}
		target, err := normalizePublishTarget(flags.Target, controlv1.Http)
		if err != nil {
			return err
		}
		if err := localproxy.PreflightWithOptions(ctx, target, localproxy.TargetOptions{}); err != nil {
			return err
		}
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			return err
		}
		body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: target}
		if flags.AllowAllIPs {
			body.AllowAllIps = &flags.AllowAllIPs
		} else if len(flags.AllowIP) != 0 {
			body.AllowIp = &flags.AllowIP
		}
		token, err := control.access(ctx)
		if err != nil {
			return err
		}
		route, err = client.AllocatePublisherPublicURL(ctx, token, body)
		if err != nil {
			return err
		}
		if !route.Ephemeral || route.TeamId != identity.TeamId || !strings.HasSuffix(route.CanonicalHostname, "."+*identity.Namespace) {
			return failure.Wrap("validate allocation", failure.ServerResponseInvalid, errors.New("control allocated a URL outside the publisher namespace"))
		}
		flags.Target = target
		// the selected publisher deletes its exact allocation on exit.
		control.route = route
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			token, err := control.access(cleanup)
			if err == nil {
				err = client.DeletePublisherPublicURL(cleanup, token, route.Id)
			}
			if err != nil && !errors.Is(err, controlclient.ErrNotFound) {
				result = errors.Join(result, err)
			}
		}()
	} else {
		return failure.Wrap("validate enrollment", failure.ServerResponseInvalid, errors.New("control returned an unknown publisher scope"))
	}
	if route.Purpose != controlv1.App || route.LifecycleState != controlv1.Enabled {
		return controlclient.ErrStatusConflict
	}
	var allocated *controlv1.PublicURL
	if route.Ephemeral {
		allocated = &route
	}
	return runSelectedPublish(ctx, flags, output, telemetry, state, server, route, control, allocated)
}
