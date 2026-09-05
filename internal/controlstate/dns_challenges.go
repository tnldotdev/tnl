package controlstate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

var ErrDNSChallengeNotFound = errors.New("controlstate: DNS challenge not found")

type DNSChallengeContext struct {
	RouteID               string
	TeamID                string
	DomainID              string
	DNSAuthorityReference string
	CanonicalDomain       string
	AuthorizationID       string
	Identifier            string
	PresentationReference string
	State                 string
	ChallengeDigest       [32]byte
	Presentations         []DNSChallengePresentation
}

type DNSChallengePresentation struct {
	ChallengeDigest [32]byte
	Active          bool
}

func (d *Database) GetDNSChallengeContext(
	ctx context.Context,
	routeID, authorizationID string,
) (DNSChallengeContext, error) {
	if !validStateText(routeID) || !validStateText(authorizationID) {
		return DNSChallengeContext{}, ErrDNSChallengeNotFound
	}
	if err := d.requireOpen(); err != nil {
		return DNSChallengeContext{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetDNSChallengeContext(ctx, controlstatedb.GetDNSChallengeContextParams{
		RouteID: routeID, AuthorizationID: authorizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSChallengeContext{}, ErrDNSChallengeNotFound
	}
	if err != nil {
		return DNSChallengeContext{}, fmt.Errorf("controlstate: get DNS challenge context: %w", err)
	}
	baseIdentifier := strings.TrimPrefix(row.Identifier, "*.")
	canonical, err := naming.CanonicalizeHostname(baseIdentifier)
	if err != nil || canonical != baseIdentifier || len(row.ChallengeDigest) != 32 ||
		!validStateText(row.PresentationReference.String) || !hostnameWithin(baseIdentifier, row.CanonicalDomain) ||
		row.CanonicalHostname != baseIdentifier && !strings.HasSuffix(row.CanonicalHostname, "."+baseIdentifier) {
		return DNSChallengeContext{}, errors.New("controlstate: invalid DNS challenge context row")
	}
	presentations, err := queries.ListDNSChallengePresentations(ctx, baseIdentifier)
	if err != nil {
		return DNSChallengeContext{}, fmt.Errorf("controlstate: list DNS challenge presentations: %w", err)
	}
	result := DNSChallengeContext{
		RouteID: row.RouteID, TeamID: row.TeamID, DomainID: row.DomainID,
		DNSAuthorityReference: row.DnsAuthorityReference.String, CanonicalDomain: row.CanonicalDomain,
		AuthorizationID: row.AuthorizationID, Identifier: row.Identifier,
		PresentationReference: row.PresentationReference.String, State: row.State,
		Presentations: make([]DNSChallengePresentation, len(presentations)),
	}
	copy(result.ChallengeDigest[:], row.ChallengeDigest)
	for index, presentation := range presentations {
		if len(presentation.ChallengeDigest) != 32 {
			return DNSChallengeContext{}, errors.New("controlstate: invalid DNS challenge presentation row")
		}
		copy(result.Presentations[index].ChallengeDigest[:], presentation.ChallengeDigest)
		result.Presentations[index].Active = presentation.State == "presenting" || presentation.State == "presented" ||
			presentation.State == "validating" || presentation.State == "valid"
	}
	return result, nil
}
