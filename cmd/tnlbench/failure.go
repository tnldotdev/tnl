package main

import (
	"context"
	"sync"
)

// Every worker phase shares one bounded first-failure capture. Call before
// stopping other public URLs so teardown cannot erase the initiating activity.
type failureCapture struct {
	ctx                         context.Context
	metricsURLs, diagnosticURLs []string
	once                        sync.Once
	diagnostics                 []databaseDiagnostic
	resources                   []resourceSample
}

func (f *failureCapture) capture() {
	f.once.Do(func() {
		f.diagnostics = sampleDatabaseDiagnostics(f.ctx, f.diagnosticURLs)
		f.resources = sampleFailureResources(f.ctx, f.metricsURLs)
	})
}
