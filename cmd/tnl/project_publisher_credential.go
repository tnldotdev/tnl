package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
)

func runProjectPublisherCredentialCreate(ctx context.Context, flags cli, output io.Writer) error {
	root, err := clientStateRoot(flags.Project.Publisher.Credential.Create.StateDir)
	if err != nil {
		return err
	}
	project, err := loadProjectConfiguration(ctx, flags, root)
	if err != nil {
		return err
	}
	selected := project.Config.Publisher
	if selected == nil || selected.Type == "local" || selected.OwnerCredentialFile == nil {
		return failure.Wrap("create publisher credential", failure.ProjectConfigMissing,
			errors.New("configure publisher.type as docker or url with owner_credential_file first"))
	}
	path := *selected.OwnerCredentialFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(project.Root, path)
	}
	credential, err := publisherCredential()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return failure.Wrap("create publisher credential directory", failure.ClientStateUnavailable, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return failure.Wrap("create publisher credential", failure.ClientStateUnavailable, err)
	}
	_, writeErr := io.WriteString(file, credential+"\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return failure.Wrap("save publisher credential", failure.ClientStateUnavailable, err)
	}
	mode := flags.Project.Publisher.Credential.Create.Output
	switch mode {
	case scalarOutputRaw:
		_, err = fmt.Fprintln(output, credential)
		return err
	case scalarOutputJSON:
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Path          string `json:"path"`
			Credential    string `json:"credential"`
		}{1, path, credential})
	default:
		if err := clioutput.Write(output, clioutput.Frame{Command: "tnl project publisher credential create", State: "created",
			Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "file", Value: path})},
			Footer: "mount the credential file read-only in the publisher",
		}); err != nil {
			return err
		}
		return nil
	}
}
