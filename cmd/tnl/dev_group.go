package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tnldotdev/tnl/internal/failure"
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

func coordinateDev(ctx context.Context, names []string, run func(context.Context, string) error) error {
	if len(names) == 0 {
		return failure.Wrap("select development services", failure.ServiceNotConfigured, errors.New("no configured services to start"))
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
	if len(names) == 1 {
		return nil
	}
	return failure.Wrap("maintain development services", failure.DevProcessFailed, fmt.Errorf("service %q stopped", first.name))
}
