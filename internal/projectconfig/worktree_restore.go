package projectconfig

import (
	"errors"
	"path/filepath"
)

// RestoreHostWorktree rebuilds the private label parts from verified host
// metadata. the owner must not generate a new salt or infer its checkout from
// the container's mount path.
func RestoreHostWorktree(w Worktree, projectRoot, primaryRoot string) (Worktree, error) {
	if !filepath.IsAbs(w.Root) || !filepath.IsAbs(projectRoot) || !filepath.IsAbs(primaryRoot) ||
		filepath.Clean(w.Root) != w.Root || filepath.Clean(projectRoot) != projectRoot || filepath.Clean(primaryRoot) != primaryRoot ||
		w.Label.ID == "" || w.Label.FullLabel == "" || !w.IsGit && primaryRoot != w.Root {
		return Worktree{}, errors.New("invalid host worktree identity")
	}
	project := w.Name
	if w.IsGit {
		project = filepath.Base(primaryRoot)
		if projectRoot != w.Root {
			rel, err := filepath.Rel(w.Root, projectRoot)
			if err != nil || rel == ".." || !pathWithin(projectRoot, w.Root) {
				return Worktree{}, errors.New("host project is outside its worktree")
			}
			project += "-" + filepath.ToSlash(rel)
		}
	}
	parts := worktreeLabelParts{project: dnsLabelStem(project, "project"), id: w.Label.ID}
	if w.IsGit && w.Root != primaryRoot {
		parts.checkout = dnsLabelStem(w.Name, "worktree")
	}
	fitted := fitWorktreeLabel("", parts)
	if w.Label.Project != fitted.project || w.Label.Checkout != fitted.checkout || w.Label.FullLabel != formatWorktreeLabel("", parts) {
		return Worktree{}, errors.New("host worktree label does not match its placement")
	}
	w.primaryRoot, w.labelParts = primaryRoot, parts
	return w, nil
}
