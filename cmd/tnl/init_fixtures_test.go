package main

import (
	"context"
	"path/filepath"
	"testing"

	projectinit "github.com/tnldotdev/tnl/internal/client/project/init"
	projectinittest "github.com/tnldotdev/tnl/internal/testutil/projectinit"
)

func planInit(ctx context.Context, root string) (projectinit.Plan, error) {
	return projectinit.NewPlan(ctx, root, func(err error) string { return presentFailure(err).action })
}

func copyInitFixture(t *testing.T, name string) string {
	t.Helper()
	return projectinittest.CopyFixture(t, filepath.Join("../../internal/client/project/init/testdata", name))
}

func genericInitFixture(t *testing.T, script, manager string) string {
	t.Helper()
	return projectinittest.GenericFixture(t, script, manager)
}

func apiInitFixture(t *testing.T, dependency, script, moduleType, source string) string {
	t.Helper()
	return projectinittest.APIFixture(t, dependency, script, moduleType, source)
}
