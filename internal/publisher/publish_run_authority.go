package publisher

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publicRunAuthority binds the secret to the complete approved setup once.
// request observers receive only PublishRunIdentity, never this authority.
type publicRunAuthority struct {
	client   PublicURLControlClient
	identity PublishRunIdentity
	token    credentials.PublishRunToken
	plan     controlv1.CertificatePlan
	teamID   string
}

func (publicRunAuthority) String() string   { return "public URL publish run authority" }
func (publicRunAuthority) GoString() string { return "public URL publish run authority" }

func bindPublicRun(config Config, setup controlv1.PublishRunSetup) (publicRunAuthority, error) {
	if setup.PublicUrl.Id == "" || setup.PublishRun.Id == "" || setup.PublishRun.PublishRunNumber <= 0 || setup.PublishRunToken == "" {
		return publicRunAuthority{}, errors.New("publisher: server returned incomplete publish run setup")
	}
	if err := validateRouteIdentity(setup.PublicUrl, config); err != nil {
		return publicRunAuthority{}, err
	}
	if setup.PublishRun.PublicUrlId != setup.PublicUrl.Id || setup.PublishRun.TeamId != setup.PublicUrl.TeamId {
		return publicRunAuthority{}, errors.New("publisher: server returned a different publish run")
	}
	if setup.PublicUrl.ServiceProtocol != controlv1.Http {
		return publicRunAuthority{}, errors.New("publisher: public HTTPS requires a certificate plan; private services use private publisher runs")
	}
	plan, err := certificateidentity.CanonicalPlan(setup.CertificatePlan)
	if err != nil || !certificateidentity.Covers(plan.Identifiers, setup.PublicUrl.CanonicalHostname) {
		return publicRunAuthority{}, errors.New("publisher: server returned an invalid certificate plan")
	}
	token := credentials.PublishRunToken(setup.PublishRunToken)
	if _, _, err := credentials.ParsePublishRunToken(token); err != nil {
		return publicRunAuthority{}, errors.New("publisher: server returned invalid publish run token")
	}
	return publicRunAuthority{client: config.Control, token: token, plan: plan, teamID: setup.PublicUrl.TeamId,
		identity: PublishRunIdentity{Hostname: setup.PublicUrl.CanonicalHostname, PublicURLID: setup.PublicUrl.Id, PublishRunID: setup.PublishRun.Id, Number: uint64(setup.PublishRun.PublishRunNumber)}}, nil
}

func (r publicRunAuthority) markReady(ctx context.Context) error {
	return r.client.MarkPublishRunReady(ctx, r.identity.PublishRunID, r.identity.Number, r.token)
}

func (r publicRunAuthority) validateHeartbeat(response controlv1.PublishRunHeartbeat) error {
	run := response.PublishRun
	if run.Id != r.identity.PublishRunID || run.PublicUrlId != r.identity.PublicURLID || run.TeamId != r.teamID ||
		run.PublishRunNumber != int64(r.identity.Number) || !run.ExpiresAt.After(time.Now()) {
		return errors.New("publisher: server returned a heartbeat for a different or expired publish run")
	}
	return nil
}

func (r publicRunAuthority) createCertificate(ctx context.Context, csr []byte, key string) (controlv1.CertificateIssuance, error) {
	return r.client.CreateCertificateIssuance(ctx, r.identity.PublishRunID, r.identity.Number, r.token, csr, key)
}

func (r publicRunAuthority) certificateInstalled(ctx context.Context, issuanceID string, notAfter time.Time) error {
	return r.client.MarkPublishRunCertificateInstalled(ctx, r.identity.PublishRunID, r.identity.Number, issuanceID, notAfter, r.token)
}

func (r publicRunAuthority) connections(ctx context.Context, config publisherConnectionManagerConfig, server *PublicURLServer) (*publisherConnectionManager, error) {
	return newPublisherConnectionManager(ctx, config, server, r.identity.PublishRunID, r.identity.PublicURLID, r.identity.Number)
}
