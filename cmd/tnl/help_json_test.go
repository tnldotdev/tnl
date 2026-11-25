package main

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"
)

func TestHelpJSONUsesDeclarationsNotParsedValues(t *testing.T) {
	root := &cobra.Command{Use: "tnl"}
	cmd := &cobra.Command{Use: "sample", Aliases: []string{"ex"}, Run: func(*cobra.Command, []string) {}}
	var options struct {
		Token   string `name:"access-token" env:"TNL_ACCESS_TOKEN"`
		Config  string `name:"config" type:"path" default:"./sample.yml"`
		Private bool   `name:"private-option" hidden:""`
	}
	options.Token = "token-from-memory"
	t.Setenv("TNL_ACCESS_TOKEN", "token-from-env")
	cliflags.Bind(cmd, &options, false)
	root.AddCommand(cmd)
	if err := cmd.ParseFlags([]string{"--access-token=token-from-argv", "--config=./other.yml"}); err != nil {
		t.Fatal(err)
	}
	target, rest := matchHelpTopic(root, []string{"ex"}, publicHelpCommand)
	if target != cmd || len(rest) != 0 {
		t.Fatalf("alias selected %v with remaining %v", target, rest)
	}
	reference := clientHelpReference(target)
	var encoded bytes.Buffer
	if err := writeHelpJSON(&encoded, reference); err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"token-from-", "other.yml", "private-option"} {
		if strings.Contains(encoded.String(), hidden) {
			t.Fatalf("leaked %q in %s", hidden, encoded.String())
		}
	}
	if !slices.Equal(reference.Path, []string{"sample"}) || !slices.Equal(reference.Aliases, []string{"ex"}) ||
		!strings.Contains(encoded.String(), `"default":"./sample.yml"`) {
		t.Fatalf("missing canonical path, alias or literal default: %s", encoded.String())
	}
}

func TestHelpJSONIndexTopicsResolveWithSharedExamples(t *testing.T) {
	root := (&commandApp{flags: &cli{}, out: io.Discard, errOut: io.Discard}).root()
	index := clientHelpIndex(root)
	for _, item := range index.Commands {
		target, rest := matchHelpTopic(root, item.Path, publicHelpCommand)
		if len(rest) != 0 {
			t.Errorf("indexed topic %q did not resolve", item.Path)
			continue
		}
		ref := clientHelpReference(target)
		examples := clientHelpExamples[target.CommandPath()]
		if len(ref.Examples) != len(examples) || len(examples) == 0 {
			t.Errorf("%q: got %d examples, expected %d nonempty examples", item.Path, len(ref.Examples), len(examples))
			continue
		}
		for i, example := range examples {
			if ref.Examples[i].Caption != example.caption ||
				!slices.Equal(ref.Examples[i].Argv, append([]string{"tnl"}, example.argv()...)) {
				t.Errorf("%q: lost shared example: %+v", item.Path, ref.Examples[i])
			}
		}
	}
}

func TestHelpJSONDiagnosticsUseOneOutputError(t *testing.T) {
	err := run(t.Context(), []string{"help", "publish", "--output=json"}, &shortHelpWriter{}, io.Discard)
	exit, render := terminalResult(err)
	var stderr bytes.Buffer
	writeCommandError(&stderr, render)
	var problem struct {
		SchemaVersion int    `json:"schema_version"`
		Type          string `json:"type"`
	}
	if exit == 0 || json.Unmarshal(stderr.Bytes(), &problem) != nil || problem.SchemaVersion != 1 || problem.Type != "error" {
		t.Fatalf("exit %d; rendered %q; error %v", exit, stderr.String(), err)
	}
}

type shortHelpWriter struct{}

func (*shortHelpWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }
