package init

import "context"

type Report struct {
	Files []FileChange `json:"files"`
	Steps []Step       `json:"steps"`
}

type FileChange struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

type Step struct {
	Kind    string   `json:"kind"`
	Status  string   `json:"status"`
	Path    string   `json:"path,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	Message string   `json:"message,omitempty"`
}

func fileStatus(edit fileEdit, preview bool) string {
	status := edit.status()
	if preview {
		switch status {
		case "created":
			return "create"
		case "updated":
			return "update"
		}
	}
	return status
}

func (r *Report) outstanding(actions []string) {
	for _, action := range actions {
		r.Steps = append(r.Steps, Step{Kind: "manual", Status: "outstanding", Message: action})
	}
}

func (r *Report) install(ctx context.Context, root, kind string, install Install, preview bool) error {
	step := Step{Kind: kind, Status: "planned", Argv: install.args}
	switch {
	case install.Manual:
		step.Status, step.Argv = "outstanding", install.manualArgs
	case !preview:
		if err := runInitInstall(ctx, root, install.args); err != nil {
			return err
		}
		step.Status = "executed"
	}
	r.Steps = append(r.Steps, step)
	return nil
}
