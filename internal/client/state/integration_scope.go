package state

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

// IntegrationScope identifies one project's integration URLs in a namespace.
// the primary project root is shared by its worktrees, not their branch names.
type IntegrationScope struct {
	PrimaryProjectRoot string
	Namespace          string
}

func (s IntegrationScope) IsZero() bool { return s == (IntegrationScope{}) }

func (s IntegrationScope) Validate() error {
	namespace, err := naming.CanonicalizeHostname(s.Namespace)
	if !filepath.IsAbs(s.PrimaryProjectRoot) || filepath.Clean(s.PrimaryProjectRoot) != s.PrimaryProjectRoot ||
		strings.ContainsRune(s.PrimaryProjectRoot, '\x00') || len(s.PrimaryProjectRoot)+len(s.Namespace) > 1023 ||
		err != nil || namespace != s.Namespace {
		return failure.Wrap("validate integration URL scope", failure.ProjectConfigInvalid, errors.New("integration scope requires a clean absolute project root and canonical namespace"))
	}
	return nil
}

func (s IntegrationScope) primaryProjectRoot() sql.NullString {
	return sql.NullString{String: s.PrimaryProjectRoot, Valid: !s.IsZero()}
}

func (s IntegrationScope) namespace() sql.NullString {
	return sql.NullString{String: s.Namespace, Valid: !s.IsZero()}
}
