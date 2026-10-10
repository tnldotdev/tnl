package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func validateEphemeralDeletion(ctx context.Context, queries *controlstatedb.Queries, token credentials.EphemeralCredential, route controlstatedb.ControlPublicUrl, now time.Time) error {
	tokenID, digest, _, err := credentials.ParseEphemeralCredential(token)
	if err != nil {
		return ErrPublicURLAccess
	}
	credential, err := queries.GetPublicURLPublishCredentialByTokenID(ctx, tokenID.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLAccess
	}
	if err != nil {
		return err
	}
	if credential.Kind != string(PublishCredentialEphemeral) || credential.RevokedAt.Valid || !credential.ExpiresAt.Time.After(now) ||
		subtle.ConstantTimeCompare(credential.TokenDigest, digest[:]) != 1 || !route.Ephemeral ||
		credential.TeamID.String != route.TeamID || credential.DomainID.String != route.DomainID ||
		credential.Namespace.String != route.Namespace || credential.IssuedByIdentityID != route.CreatedByIdentityID {
		return ErrPublicURLAccess
	}
	allocation, err := queries.GetEphemeralPublicURLAllocation(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLAccess
	}
	if err != nil {
		return err
	}
	if allocation.CredentialID != credential.ID {
		return ErrPublicURLAccess
	}
	return nil
}
