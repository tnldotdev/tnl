package runtime

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

// PrepareSnapshot is the explicit assertion -> service preparation -> atomic
// snapshot operation. local SDK selection and owner IPC use this same boundary.
func PrepareSnapshot(ctx context.Context, backend PreparationBackend, request Request) (Prepared, error) {
	if request.Assertion != "" || request.AcquireAssertion {
		if err := backend.UseAssertion(ctx, request.Assertion); err != nil {
			return Prepared{}, err
		}
	}
	_, err := backend.Connect(ctx, request.Service)
	if err != nil {
		return Prepared{}, err
	}
	return backend.SnapshotFor(request.Service, request.Assertion)
}

// ValidatePrepared is the native SDK wire boundary. a read never calls it to
// repair state; selected owners must publish a valid, coherent snapshot first.
func ValidatePrepared(p Prepared, service string) error {
	c, m := p.Connection, p.ProjectRuntime
	metadata := meta.Metadata{Version: meta.Version, Namespace: m.Namespace, Worktree: m.Worktree, Services: m.Services, OAuth: m.OAuth, Webhooks: m.Webhooks, Aliases: m.Aliases}
	if p.Schema != Schema || c.Schema != Schema || len(m.Services) > 32 || metadata.Validate() != nil || c.Host != "127.0.0.1" || c.Port < 1 || c.Port > 65535 {
		return ErrInvalid
	}
	endpoint, found := m.Services[service]
	if !found || c.Protocol != endpoint.Protocol {
		return ErrInvalid
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Protocol == "tcp" {
		if c.SSL != nil || c.URL != "" || c.Kubeconfig != "" || c.Context != "" {
			return ErrInvalid
		}
	} else {
		if c.SSL == nil || !c.SSL.RejectUnauthorized || c.SSL.ServerName != endpoint.Hostname || len(c.SSL.CA) > 32<<10 {
			return ErrInvalid
		}
		if c.Protocol == "http" || c.Protocol == "kubernetes" {
			if c.URL != endpoint.URL {
				return ErrInvalid
			}
		} else if c.URL != "" {
			return ErrInvalid
		}
		if c.Protocol == "kubernetes" {
			if !filepath.IsAbs(c.Kubeconfig) || len(c.Kubeconfig) > 4096 || strings.ContainsRune(c.Kubeconfig, 0) || !strings.HasPrefix(c.Context, "tnl:") || len(c.Context) > 1024 {
				return ErrInvalid
			}
		} else if c.Kubeconfig != "" || c.Context != "" {
			return ErrInvalid
		}
	}
	if v := p.Verification; v != nil {
		if len(v.Digest) != 64 || len(v.Binding) != 64 || !v.ExpiresAt.After(time.Now()) || v.ExpiresAt.After(time.Now().Add(12*time.Hour+time.Minute)) {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(v.Digest); err != nil {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(v.Binding); err != nil {
			return ErrInvalid
		}
	}
	return nil
}
