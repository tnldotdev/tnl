package init

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tailscale/hujson"
)

func TestProjectTypeIncludesEditJSONCSyntaxWithoutRewritingOtherFields(t *testing.T) {
	for _, test := range []struct {
		name, source, field string
		want                []string
		manual              bool
	}{
		{"compact", `{"compilerOptions":{"strict":true},"include":["src"]}`, "include", []string{"src", ".tnl/generated/project.d.ts"}, false},
		{"trailing_comments", "{\r\n  \"compilerOptions\" /* name */: /* value */ {\"strict\":true},\r\n  \"include\": [\r\n    \"src\" /* source */ , // prior entry\r\n    /* keep final comment */\r\n  ],\r\n  \"exclude\": [\"dist\"],\r\n}", "include", []string{"src", ".tnl/generated/project.d.ts"}, false},
		{"before_closing", "{\n  \"include\": [\n    \"src\" // prior entry\n  ]\n}\n", "include", []string{"src", ".tnl/generated/project.d.ts"}, false},
		{"empty_commented", `{"include":[/* source list */]}`, "include", []string{".tnl/generated/project.d.ts"}, false},
		{"default_glob", `{"compilerOptions":{"strict":true}}`, "include", []string{"**/*", ".tnl/generated/project.d.ts"}, false},
		{"files_only", `{"files":["src/main.ts"]}`, "files", []string{"src/main.ts", ".tnl/generated/project.d.ts"}, false},
		{"inherited", `{"extends":"./base.json","compilerOptions":{"strict":true}}`, "", nil, true},
		{"explicit_inherited", `{"extends":"./base.json","include":["src"]}`, "include", []string{"src", ".tnl/generated/project.d.ts"}, false},
		{"null_include", `{"include":null}`, "", nil, true},
		{"duplicate", `{"include":["src"],"include":["other"]}`, "", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tsconfig.json")
			if err := os.WriteFile(path, []byte(test.source), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := wireProjectTypeIncludes(root)
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.manual {
				if len(result.actions) != 1 || len(result.updated) != 0 || string(after) != test.source {
					t.Fatalf("complex config was changed: %s %+v", after, result)
				}
				return
			}
			if len(result.actions) != 0 || len(result.updated) != 1 {
				t.Fatalf("include was not wired: %+v", result)
			}
			beforeAST, err := hujson.Parse([]byte(test.source))
			if err != nil {
				t.Fatal(err)
			}
			afterAST, err := hujson.Parse(after)
			if err != nil {
				t.Fatal(err)
			}
			for _, pointer := range []string{"/compilerOptions", "/exclude", "/extends"} {
				if before := beforeAST.Find(pointer); before != nil {
					if changed := afterAST.Find(pointer); changed == nil || !bytes.Equal(before.Pack(), changed.Pack()) {
						t.Fatal("unrelated syntax changed", pointer)
					}
				}
			}
			for _, comment := range []string{"/* name */", "/* value */", "/* source */", "// prior entry", "/* keep final comment */", "/* source list */"} {
				if bytes.Count([]byte(test.source), []byte(comment)) != bytes.Count(after, []byte(comment)) {
					t.Fatal("comment was lost or duplicated", comment)
				}
			}
			standard := afterAST.Clone()
			standard.Standardize()
			var fields map[string]jsontext.Value
			if err := json.Unmarshal(standard.Pack(), &fields); err != nil {
				t.Fatal(err)
			}
			var includes []string
			if err := json.Unmarshal(fields[test.field], &includes); err != nil || !slices.Equal(includes, test.want) {
				t.Fatalf("wired sources = %v %v", includes, err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("mode changed")
			}
			repeated, err := wireProjectTypeIncludes(root)
			if err != nil || len(repeated.actions) != 0 || len(repeated.updated) != 0 {
				t.Fatalf("repeat = %+v %v", repeated, err)
			}
			again, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, again) {
				t.Fatal("repeat changed JSONC", err)
			}
			nextInfo, err := os.Stat(path)
			if err != nil || !info.ModTime().Equal(nextInfo.ModTime()) {
				t.Fatal("repeat rewrote tsconfig", err)
			}
		})
	}
}

func TestProjectTypeIncludesRejectSymlinkFilesAndReferenceParents(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "reference_parent"}[parentLink], func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			source := []byte(`{"include":["src"]}`)
			if err := os.WriteFile(filepath.Join(outside, "tsconfig.json"), source, 0600); err != nil {
				t.Fatal(err)
			}
			if parentLink {
				if err := os.Symlink(outside, filepath.Join(root, "app")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "tsconfig.json"), []byte(`{"files":[],"references":[{"path":"app"}]}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(filepath.Join(outside, "tsconfig.json"), filepath.Join(root, "tsconfig.json")); err != nil {
				t.Fatal(err)
			}
			result, err := wireProjectTypeIncludes(root)
			if err != nil || len(result.actions) != 1 || len(result.updated) != 0 {
				t.Fatalf("unsafe include = %+v %v", result, err)
			}
			after, err := os.ReadFile(filepath.Join(outside, "tsconfig.json"))
			if err != nil || !bytes.Equal(source, after) {
				t.Fatal("wrote through symlink", err)
			}
		})
	}
}
