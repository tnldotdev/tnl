package projectconfig

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestResolveWorktreePreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ResolveWorktree(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveWorktree error = %v, want context.Canceled", err)
	}
}

func TestResolveWorktreePreservesGitCommandDeadline(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec sleep 60\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := ResolveWorktree(ctx, t.TempDir()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveWorktree error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestWorktreeNamesUseProjectAndCheckoutNotBranch(t *testing.T) {
	parent := t.TempDir()
	primary := filepath.Join(parent, "shop")
	linked := filepath.Join(parent, "perf")
	if err := os.Mkdir(primary, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeWorktreeTestRepo(t, primary)
	runWorktreeGit(t, primary, "worktree", "add", "--detach", linked)

	salt := [32]byte{1}
	mainWorktree, err := ResolveWorktree(t.Context(), primary)
	if err != nil {
		t.Fatal(err)
	}
	mainWorktree = ApplyWorktreeHashSalt(mainWorktree, primary, salt)
	canonicalPrimary, err := filepath.EvalSymlinks(primary)
	if err != nil {
		t.Fatal(err)
	}
	if !mainWorktree.IsGit || mainWorktree.Root != canonicalPrimary || mainWorktree.Name != "shop" ||
		!strings.HasPrefix(mainWorktree.Label, "shop-") ||
		ServiceWorktreeLabel("web", mainWorktree) != "web-"+mainWorktree.Label {
		t.Fatalf("primary worktree = %#v", mainWorktree)
	}
	alias := filepath.Join(parent, "shop-alias")
	if err := os.Symlink(primary, alias); err != nil {
		t.Fatal(err)
	}
	aliased, err := ResolveWorktree(t.Context(), alias)
	if err != nil {
		t.Fatal(err)
	}
	aliased = ApplyWorktreeHashSalt(aliased, alias, salt)
	if !aliased.IsGit || aliased.Label != mainWorktree.Label {
		t.Fatalf("aliased primary worktree = %#v", aliased)
	}
	linkedWorktree, err := ResolveWorktree(t.Context(), linked)
	if err != nil {
		t.Fatal(err)
	}
	linkedWorktree = ApplyWorktreeHashSalt(linkedWorktree, linked, salt)
	canonicalLinked, err := filepath.EvalSymlinks(linked)
	if err != nil {
		t.Fatal(err)
	}
	if !linkedWorktree.IsGit || linkedWorktree.Root != canonicalLinked || linkedWorktree.Name != "perf" ||
		!strings.HasPrefix(linkedWorktree.Label, "shop-perf-") ||
		ServiceWorktreeLabel("web", linkedWorktree) != "web-"+linkedWorktree.Label ||
		linkedWorktree.Label == mainWorktree.Label {
		t.Fatalf("linked worktree = %#v", linkedWorktree)
	}
	for _, root := range []string{primary, linked} {
		if err := os.MkdirAll(filepath.Join(root, "apps", "web"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if linkedWorktree.PrimaryCheckoutRoot() != canonicalPrimary ||
		SharedProjectIdentity(linkedWorktree, filepath.Join(linked, "apps", "web")) != filepath.Join(canonicalPrimary, "apps", "web") ||
		SharedProjectIdentity(mainWorktree, filepath.Join(primary, "apps", "web")) != filepath.Join(canonicalPrimary, "apps", "web") {
		t.Fatalf("primary = %q, linked primary = %q, linked project = %q, main project = %q", canonicalPrimary,
			linkedWorktree.PrimaryCheckoutRoot(), SharedProjectIdentity(linkedWorktree, filepath.Join(linked, "apps", "web")),
			SharedProjectIdentity(mainWorktree, filepath.Join(primary, "apps", "web")))
	}
	if SharedProjectLabel("oauth", mainWorktree, primary, salt) == ServiceWorktreeLabel("oauth", mainWorktree) {
		t.Fatal("callback hostname collides with a project service named oauth")
	}
	for _, relative := range []string{".", "apps/store"} {
		mainProject := filepath.Join(primary, relative)
		linkedProject := filepath.Join(linked, relative)
		if first, second := SharedProjectLabel("oauth", mainWorktree, mainProject, salt),
			SharedProjectLabel("oauth", linkedWorktree, linkedProject, salt); first != second {
			t.Fatalf("shared callback labels differ for %s: %q != %q", relative, first, second)
		}
		if first, second := SharedProjectIdentity(mainWorktree, mainProject),
			SharedProjectIdentity(linkedWorktree, linkedProject); first != second {
			t.Fatalf("shared project identities differ for %s: %q != %q", relative, first, second)
		}
	}
	runWorktreeGit(t, linked, "switch", "-c", "new-branch")
	changedBranch, err := ResolveWorktree(t.Context(), linked)
	if err != nil {
		t.Fatal(err)
	}
	changedBranch = ApplyWorktreeHashSalt(changedBranch, linked, salt)
	if changedBranch.Label != linkedWorktree.Label {
		t.Fatalf("branch switch changed the worktree label: %q -> %q", linkedWorktree.Label, changedBranch.Label)
	}

	projectRoot := filepath.Join(linked, "apps", "store")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	nested, err := ResolveWorktree(t.Context(), projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	nested = ApplyWorktreeHashSalt(nested, projectRoot, salt)
	if !strings.HasPrefix(nested.Label, "shop-apps-store-perf-") || nested.Label == linkedWorktree.Label {
		t.Fatalf("nested project = %#v", nested)
	}
	configPath := filepath.Join(projectRoot, "tnl.json")
	if err := os.WriteFile(configPath, []byte(`{"version":1,"tnl":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := Resolve(t.Context(), Selection{Path: configPath}, projectRoot, salt)
	if err != nil || project.Worktree.Label != nested.Label || project.Root != projectRoot {
		t.Fatalf("resolved project = %#v, %v", project, err)
	}
	otherRoot := filepath.Join(linked, "apps", "admin")
	if err := os.MkdirAll(otherRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	other := ApplyWorktreeHashSalt(nested, otherRoot, salt)
	if !strings.HasPrefix(other.Label, "shop-apps-admin-perf-") || other.Label == nested.Label {
		t.Fatalf("other project = %#v", other)
	}

	billing := filepath.Join(parent, "billing ")
	if err := os.Mkdir(billing, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeWorktreeTestRepo(t, billing)
	secondDirectory := filepath.Join(parent, "other-checkouts")
	if err := os.Mkdir(secondDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	secondLinked := filepath.Join(secondDirectory, "perf")
	runWorktreeGit(t, billing, "worktree", "add", "--detach", secondLinked)
	billingWorktree, err := ResolveWorktree(t.Context(), secondLinked)
	if err != nil {
		t.Fatal(err)
	}
	billingWorktree = ApplyWorktreeHashSalt(billingWorktree, secondLinked, salt)
	if !strings.HasPrefix(billingWorktree.Label, "billing-perf-") || billingWorktree.Label == linkedWorktree.Label {
		t.Fatalf("other repository = %#v", billingWorktree)
	}
}

func TestWorktreeLabelUsesStateAndProjectRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "Café Shop")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	worktree, err := ResolveWorktree(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	first := ApplyWorktreeHashSalt(worktree, root, [32]byte{1})
	if first.IsGit || !regexp.MustCompile(`^cafe-shop-[0-9a-z]{6}$`).MatchString(first.Label) ||
		ServiceWorktreeLabel("api", first) != "api-"+first.Label ||
		ApplyWorktreeHashSalt(worktree, root, [32]byte{1}).Label != first.Label {
		t.Fatalf("non-Git project label = %q", first.Label)
	}
	if changed := ApplyWorktreeHashSalt(worktree, root, [32]byte{2}); changed.Label == first.Label {
		t.Fatalf("different client state kept label %q", changed.Label)
	}
	if changed := ApplyWorktreeHashSalt(worktree, filepath.Join(root, "other"), [32]byte{1}); changed.Label == first.Label {
		t.Fatalf("different project root kept label %q", changed.Label)
	}
	secondRoot := filepath.Join(parent, "other", "Café Shop")
	if err := os.MkdirAll(secondRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	secondWorktree, err := ResolveWorktree(t.Context(), secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	secondWorktree = ApplyWorktreeHashSalt(secondWorktree, secondRoot, [32]byte{1})
	if !strings.HasPrefix(secondWorktree.Label, "cafe-shop-") || secondWorktree.Label == first.Label {
		t.Fatalf("same-named project in another directory = %q", secondWorktree.Label)
	}
}

func TestServiceWorktreeLabelKeepsEachPartUnderDNSLimit(t *testing.T) {
	parts := worktreeLabelParts{
		project:  dnsLabelStem("Long Café Shop "+strings.Repeat("project", 10), "project"),
		checkout: dnsLabelStem("Perf Feature "+strings.Repeat("worktree", 10), "worktree"),
		id:       "k7n2p9",
	}
	worktree := Worktree{labelParts: parts, Label: formatWorktreeLabel("", parts)}
	for _, service := range []string{"", "web", strings.Repeat("a", 32)} {
		label := ServiceWorktreeLabel(service, worktree)
		if len(label) > 63 || !strings.HasSuffix(label, "-k7n2p9") ||
			!strings.Contains(label, "cafe") || !strings.Contains(label, "perf") ||
			!regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`).MatchString(label) {
			t.Fatalf("service %q produced invalid label %q", service, label)
		}
	}
	if value := dnsLabelStem("💫", "project"); value != "project" {
		t.Fatalf("non-ASCII name = %q", value)
	}
}

func runWorktreeGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=tnl test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=tnl test", "GIT_COMMITTER_EMAIL=test@example.com")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

func initializeWorktreeTestRepo(t *testing.T, primary string) {
	t.Helper()
	runWorktreeGit(t, "", "init", "--initial-branch=main", primary)
	tree := runWorktreeGit(t, primary, "mktree")
	commit := runWorktreeGit(t, primary, "commit-tree", tree, "-m", "fixture")
	runWorktreeGit(t, primary, "update-ref", "refs/heads/main", commit)
}
