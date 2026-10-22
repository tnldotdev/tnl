package target

import (
	"context"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

func RuntimeTargetBinding(project projectconfig.Project, name, reported string, changed func(), resolver TargetResolver) *TargetBinding {
	return &TargetBinding{Changed: changed, Resolve: func(ctx context.Context) (TargetSnapshot, error) {
		if reported != "" && config.TargetType(project.Config.Services[name]) == "app" {
			address, err := targetsyntax.NormalizeTarget(reported)
			return TargetSnapshot{Address: address, Identity: address}, err
		}
		return ResolveTargetSnapshot(ctx, project, name, resolver)
	}}
}
