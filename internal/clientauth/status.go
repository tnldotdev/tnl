package clientauth

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

type StatusResult struct {
	SchemaVersion    int        `json:"schema_version"`
	Server           string     `json:"server"`
	Status           string     `json:"status"`
	Source           string     `json:"source"`
	AccessExpiresAt  *time.Time `json:"access_expires_at,omitempty"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`
	Checked          bool       `json:"checked"`
}

// Status is local unless check is requested. checking may refresh credentials
// and validate with control, but never initiates approval or browser login.
func Status(ctx context.Context, config Config, check bool) (StatusResult, error) {
	server, err := clientstate.CanonicalServer(config.ServerEndpoint)
	result := StatusResult{SchemaVersion: 1, Server: server, Status: "unauthenticated", Source: "none"}
	if err != nil {
		return result, err
	}
	config.ServerEndpoint = server
	if config.AccessToken != "" {
		if err := validateExplicitToken(config.AccessToken); err != nil {
			return result, err
		}
		result.Status, result.Source = "available", "explicit_access_token"
	} else {
		store, err := authStore(ctx, config)
		if err != nil {
			return result, err
		}
		session, found, err := store.ControlSession(ctx)
		if err != nil {
			return result, err
		}
		if found {
			result.Source = "saved_session"
			result.AccessExpiresAt, result.RefreshExpiresAt = &session.AccessExpiresAt, &session.RefreshExpiresAt
			result.Status = "available"
			if !session.AccessExpiresAt.After(time.Now()) {
				result.Status = "refresh_required"
			}
			if !session.RefreshExpiresAt.After(time.Now()) {
				result.Status = "expired"
			}
			if session.RefreshPending {
				result.Status = "recovery_required"
			}
		}
	}
	if check {
		client, err := Authenticate(ctx, config)
		if err != nil {
			return result, err
		}
		if _, err := client.Authority.IdentityContext(ctx); err != nil {
			return result, err
		}
		result, err = Status(ctx, config, false)
		result.Checked, result.Status = true, "authenticated"
		return result, err
	}
	return result, nil
}
