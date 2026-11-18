//go:build !js || !wasm

package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

func (m *Metrics) initLogs(config Config, res *resource.Resource, state *exportState) error {
	if config.Disabled || config.Logs.Endpoint == "" {
		return nil
	}
	s := config.Logs
	compression := otlploghttp.NoCompression
	if s.Gzip {
		compression = otlploghttp.GzipCompression
	}
	e, err := otlploghttp.New(context.Background(), otlploghttp.WithEndpointURL(s.Endpoint), otlploghttp.WithHTTPClient(s.client()), otlploghttp.WithHeaders(s.Headers), otlploghttp.WithCompression(compression), otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: s.Timeout}))
	if err != nil {
		return safeExportError("initialize log export", err)
	}
	queue, batch, delay := config.LogQueueSize, config.LogBatchSize, config.LogBatchDelay
	if queue <= 0 {
		queue = 2048
	}
	if batch <= 0 {
		batch = 512
	}
	if delay <= 0 {
		delay = time.Second
	}
	m.logProcessor = sdklog.NewBatchProcessor(&logExporter{e, state}, sdklog.WithMaxQueueSize(queue), sdklog.WithExportMaxBatchSize(min(batch, queue)), sdklog.WithExportInterval(delay), sdklog.WithExportTimeout(s.Timeout))
	m.loggerProvider = sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithAttributeCountLimit(32), sdklog.WithAttributeValueLengthLimit(256), sdklog.WithProcessor(m.logProcessor))
	return nil
}

type logExporter struct {
	sdklog.Exporter
	state *exportState
}

func (e *logExporter) Export(ctx context.Context, records []sdklog.Record) error {
	ctx, cancel := e.state.exportContext(ctx)
	defer cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := e.Exporter.Export(ctx, records); err != nil {
		e.state.logFailures.Add(1)
		return safeExportError("log export failed", err)
	}
	return nil
}
