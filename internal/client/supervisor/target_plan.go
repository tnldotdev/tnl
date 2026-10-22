package supervisor

import "github.com/tnldotdev/tnl/internal/publisher/target"

func (j Job) TargetPlan() target.TargetPlan {
	return target.TargetPlan{Protocol: j.Protocol, Target: j.Target, Trust: j.Trust, Project: j.Project, ProjectService: j.ProjectService}
}
