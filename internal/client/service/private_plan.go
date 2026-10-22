package publisherjob

import "github.com/tnldotdev/tnl/internal/publisher/target"

func (j Job) PrivateTargetPlan() target.PrivateTargetPlan {
	return target.PrivateTargetPlan{Protocol: j.Protocol, Target: j.Target, Trust: j.Trust, Project: j.Project, ProjectService: j.ProjectService}
}
