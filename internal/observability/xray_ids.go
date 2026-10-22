package observability

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// xrayIDGenerator gives locally created root traces the X-Ray timestamp prefix
// and 96 random bits. propagated parent IDs remain unchanged. SDK formatting
// compatibility does not qualify a deployed collector or an AWS export pipeline.
type xrayIDGenerator struct{}

func (xrayIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	var id trace.TraceID
	_, _ = rand.Read(id[4:])
	binary.BigEndian.PutUint32(id[:4], uint32(time.Now().Unix()))
	return id, xrayIDGenerator{}.NewSpanID(ctx, id)
}

func (xrayIDGenerator) NewSpanID(context.Context, trace.TraceID) trace.SpanID {
	var id trace.SpanID
	for !id.IsValid() {
		_, _ = rand.Read(id[:])
	}
	return id
}
