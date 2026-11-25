package init

import (
	"context"
	"path/filepath"
	"testing"

	projectinittest "github.com/tnldotdev/tnl/internal/testutil/projectinit"
)

// these test-only adapters keep the original assertions independent of command
// presentation while the production API accepts a diagnostic action formatter.
func planInit(ctx context.Context, root string) (Plan, error) {
	return NewPlan(ctx, root, func(err error) string { return err.Error() })
}

func ensureTnlGitignore(root string) (bool, error) {
	edit, err := planTnlGitignore(root)
	if err != nil {
		return false, err
	}
	return edit.replacement != nil, edit.apply()
}

func wireProjectTypeIncludes(root string) (projectTypeIncludeResult, error) {
	return visitProjectTypeIncludes(root, fileEdit.apply)
}

func copyInitFixture(t *testing.T, name string) string {
	t.Helper()
	return projectinittest.CopyFixture(t, filepath.Join("testdata", name))
}

func genericInitFixture(t *testing.T, script, manager string) string {
	t.Helper()
	return projectinittest.GenericFixture(t, script, manager)
}

func apiInitFixture(t *testing.T, dependency, script, moduleType, source string) string {
	t.Helper()
	return projectinittest.APIFixture(t, dependency, script, moduleType, source)
}
