package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/tnldotdev/tnl/internal/projectmeta"
)

// devMetadataWriter keeps the project metadata file consistent while each
// service starts its own local process and publisher connection.
type devMetadataWriter struct {
	once sync.Once
	err  error
}

func (w *devMetadataWriter) write(ctx context.Context, root string, metadata projectmeta.Metadata) error {
	w.once.Do(func() { w.err = projectmeta.Write(ctx, root, metadata) })
	return w.err
}

func runCoordinatedDev(ctx context.Context, project projectConfiguration, flags devCommand, stdin io.Reader, stdout, stderr io.Writer, reporters ...telemetryReporter) error {
	if len(flags.Command) != 0 || flags.Port != 0 || flags.StartupTimeout != 0 || flags.PublicURL != "" || flags.Name != "" || flags.Domain != "" || flags.Ephemeral || flags.AllowAllIPs || flags.AllowIP != nil || flags.AllowProvider != nil || flags.RequestLimit != nil {
		return errors.New("select a service when overriding its command, port, or public URL settings")
	}
	names := make([]string, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	writer := &devMetadataWriter{}
	targets := newDevGroupTargets(len(names))
	return coordinateDev(ctx, names, func(runCtx context.Context, name string) error {
		serviceFlags := flags
		serviceFlags.Service = name
		serviceFlags.metadataWriter = writer
		serviceFlags.groupTargets = targets
		serviceFlags.coordinated = true
		if err := project.applyDev(&serviceFlags); err != nil {
			return err
		}
		return runDev(runCtx, serviceFlags, stdin, stdout, stderr, reporters...)
	})
}

func coordinateDev(ctx context.Context, names []string, run func(context.Context, string) error) error {
	if len(names) == 0 {
		return errors.New("no configured services to start")
	}
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(names))
	for _, name := range names {
		go func() { results <- result{name: name, err: run(ctx, name)} }()
	}
	first := <-results
	cancel()
	for index := 1; index < len(names); index++ {
		<-results
	}
	if parent.Err() != nil {
		return context.Cause(parent)
	}
	if err := first.err; err != nil {
		return fmt.Errorf("service %q: %w", first.name, err)
	}
	return fmt.Errorf("service %q stopped", first.name)
}
