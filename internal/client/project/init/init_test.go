package init

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestInitApplyOwnsInstallEditsGenerationAndTypeWiringOrder(t *testing.T) {
	for _, noInstall := range []bool{false, true} {
		t.Run(fmt.Sprintf("no_install_%t", noInstall), func(t *testing.T) {
			root, bin := t.TempDir(), t.TempDir()
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			log := filepath.Join(t.TempDir(), "operations")
			t.Setenv("INIT_OPERATIONS_LOG", log)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			write := func(path, data string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(data), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "package.json"), `{"packageManager":"pnpm@1","devDependencies":{"vite":"6"}}`, 0o600)
			write(filepath.Join(root, "pyproject.toml"), "[project]\nname = 'example'\nversion = '0.0.0'\n", 0o600)
			tsconfig := "{\n  // keep source patterns\n  \"include\": [\"src\"]\n}\n"
			write(filepath.Join(root, "tsconfig.json"), tsconfig, 0o600)
			write(filepath.Join(bin, "pnpm"), "#!/bin/sh\n[ ! -e tnl.config.ts ] || exit 70\nprintf 'pnpm:%s:%s:%s\\n' \"$PWD\" \"$NO_COLOR\" \"$*\" >> \"$INIT_OPERATIONS_LOG\"\nprintf 'discard package manager output\\n'\n", 0o700)
			write(filepath.Join(bin, "uv"), "#!/bin/sh\n[ -f .tnl/generated/python-ready ] || exit 71\nprintf 'uv:%s:%s:%s\\n' \"$PWD\" \"$NO_COLOR\" \"$*\" >> \"$INIT_OPERATIONS_LOG\"\n", 0o700)
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			generationCalls := 0
			result, err := plan.Apply(t.Context(), Options{
				NoInstall: noInstall,
				Generate: func(ctx context.Context, selectedRoot, path string) error {
					generationCalls++
					if selectedRoot != root || path != filepath.Join(root, "tnl.config.ts") || ctx != t.Context() {
						t.Fatalf("generation selection = %s, %s", selectedRoot, path)
					}
					for _, name := range []string{"tnl.config.ts", "vite.config.ts", ".gitignore"} {
						if _, err := os.Stat(filepath.Join(root, name)); err != nil {
							t.Fatalf("generation preceded source edit %s: %v", name, err)
						}
					}
					if data, err := os.ReadFile(filepath.Join(root, "tsconfig.json")); err != nil || string(data) != tsconfig {
						t.Fatalf("types were wired before generation: %s, %v", data, err)
					}
					if err := os.MkdirAll(filepath.Join(root, ".tnl/generated"), 0o755); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(root, ".tnl/generated/python-ready"), nil, 0o600)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if generationCalls != 1 || !result.Changed || !result.ConfigurationCreated || result.Root != root || result.ConfigurationPath != plan.ConfigurationPath || result.DeclarationsPath != filepath.Join(root, ".tnl/generated/project.d.ts") || result.PythonPackagePath != filepath.Join(root, ".tnl/generated/python") ||
				!slices.Equal(result.UpdatedPaths, []string{filepath.Join(root, "vite.config.ts"), filepath.Join(root, ".gitignore"), filepath.Join(root, "tsconfig.json")}) {
				t.Fatalf("result = %+v; generation calls = %d", result, generationCalls)
			}
			if data, err := os.ReadFile(filepath.Join(root, "tsconfig.json")); err != nil || !bytes.Contains(data, []byte(".tnl/generated/project.d.ts")) || !bytes.Contains(data, []byte("// keep source patterns")) {
				t.Fatalf("type wiring = %s, %v", data, err)
			}
			data, err := os.ReadFile(log)
			if noInstall {
				if !errors.Is(err, os.ErrNotExist) || len(result.InstalledPackages) != 0 || !slices.Equal(result.Actions, []string{"Run: pnpm add --save-dev @tnldotdev/tnl", "run in the Python project: uv add --editable ./.tnl/generated/python"}) {
					t.Fatalf("no-install result = %+v, invocation = %s, %v", result, data, err)
				}
			} else {
				canonical, err := filepath.EvalSymlinks(root)
				if err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprintf("pnpm:%s:1:add --save-dev --reporter=silent @tnldotdev/tnl\nuv:%s:1:add --editable ./.tnl/generated/python\n", canonical, canonical)
				if string(data) != want || !slices.Equal(result.InstalledPackages, []string{"@tnldotdev/tnl"}) || len(result.Actions) != 0 {
					t.Fatalf("result = %+v, invocation = %q, want %q", result, data, want)
				}
			}
			if len(plan.Actions) != 0 {
				t.Fatalf("applying mutated planned actions: %v", plan.Actions)
			}
		})
	}
}

func TestInitApplyStopsBeforePythonAndTypesWhenGenerationFails(t *testing.T) {
	root := genericInitFixture(t, "", "npm")
	path := filepath.Join(root, "tsconfig.json")
	source := []byte(`{"include":["src"]}`)
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\nname = 'example'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "uv-called")
	t.Setenv("INIT_UV_MARKER", marker)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(bin, "uv"), []byte("#!/bin/sh\nprintf called > \"$INIT_UV_MARKER\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("generation stopped")
	_, err = plan.Apply(t.Context(), Options{Generate: func(context.Context, string, string) error { return want }})
	if !errors.Is(err, want) {
		t.Fatalf("generation cause = %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, source) {
		t.Fatalf("failed generation edited types: %s, %v", data, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed generation ran Python installation: %v", err)
	}
}

func TestInitDetectionDiagnosticsUseCallerActionsAndKeepReasons(t *testing.T) {
	root := copyInitFixture(t, "next")
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"next":"1","vite":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "next.config.ts")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reasons []failure.Reason
	plan, err := NewPlan(t.Context(), root, func(err error) string {
		reason, ok := failure.ReasonOf(err)
		if !ok {
			t.Fatalf("unclassified diagnostic: %v", err)
		}
		reasons = append(reasons, reason)
		return "caller action: " + string(reason)
	})
	if err != nil || !slices.Equal(reasons, []failure.Reason{failure.InitPackageManager, failure.InitFramework}) || len(plan.Actions) != 2 || !plan.InstallBlocked || plan.NeedsAppRegistration {
		t.Fatalf("plan = %+v, reasons = %v, err = %v", plan, reasons, err)
	}
	for i, reason := range reasons {
		if plan.Actions[i] != "caller action: "+string(reason) {
			t.Fatalf("caller action was reformatted: %v", plan.Actions)
		}
	}
}

func TestInitApplyRefusesServerChangedAfterPlanning(t *testing.T) {
	root := apiInitFixture(t, "express", "tsx src/index.ts", "module", "import express from 'express'\nconst app = express()\napp.listen(3000)\n")
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	custom := []byte("// developer edit\n" + string(plan.ServerSource))
	if err := os.WriteFile(plan.ServerPath, custom, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = plan.Apply(t.Context(), Options{NoInstall: true, Generate: func(context.Context, string, string) error {
		t.Fatal("generated after refusing changed source")
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "changed during initialization") {
		t.Fatalf("changed source error = %v", err)
	}
	if after, err := os.ReadFile(plan.ServerPath); err != nil || !bytes.Equal(after, custom) {
		t.Fatalf("changed server was overwritten: %s, %v", after, err)
	}
}
