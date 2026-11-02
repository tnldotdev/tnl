package control

import (
	"context"
	"errors"
	"math"
	"net/http"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ReportPublisherServiceObservations(ctx context.Context, runID string, number uint64, token credentials.PublishRunToken, batch serviceaudit.Batch) error {
	if number == 0 || number > math.MaxInt64 || token == "" {
		return errors.Join(serviceaudit.ErrRejected, serviceaudit.ErrInvalid)
	}
	events, err := serviceaudit.APIObservations(batch)
	if err != nil {
		return errors.Join(serviceaudit.ErrRejected, err)
	}
	for _, e := range batch.Events {
		if e.RunID != runID || e.RunNumber != int64(number) || e.EventType != "http.decision" || e.ServiceKind != "public_url" || e.PairID != "" {
			return errors.Join(serviceaudit.ErrRejected, serviceaudit.ErrInvalid)
		}
	}
	status := 0
	result, err := request[controlv1.ServiceObservationResult](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		response, err := c.api.ReportPublishRunServiceObservations(ctx, runID, controlv1.PublishRunServiceObservations{PublishRunNumber: int64(number), Events: events}, editors...)
		if response != nil {
			status = response.StatusCode
		}
		return response, err
	})
	if err != nil {
		return serviceAuditReportError(ctx, status, err)
	}
	return serviceaudit.ValidateAcknowledgement(result.Accepted, result.Duplicates, len(events))
}

func (c *Client) ReportServiceRunObservations(ctx context.Context, serviceID, runID string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	if number < 1 || token == "" {
		return errors.Join(serviceaudit.ErrRejected, serviceaudit.ErrInvalid)
	}
	events, err := serviceaudit.APIObservations(batch)
	if err != nil {
		return errors.Join(serviceaudit.ErrRejected, err)
	}
	for _, e := range batch.Events {
		if e.ServiceID != serviceID || e.RunID != runID || e.RunNumber != number || e.ServiceKind != "service" || e.PairID == "" || e.EventType != "connection.open" && e.EventType != "connection.close" {
			return errors.Join(serviceaudit.ErrRejected, serviceaudit.ErrInvalid)
		}
	}
	status := 0
	result, err := request[controlv1.ServiceObservationResult](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		response, err := c.api.ReportServiceRunObservations(ctx, serviceID, runID, controlv1.ServiceRunObservations{RunNumber: number, Events: events}, editors...)
		if response != nil {
			status = response.StatusCode
		}
		return response, err
	})
	if err != nil {
		return serviceAuditReportError(ctx, status, err)
	}
	return serviceaudit.ValidateAcknowledgement(result.Accepted, result.Duplicates, len(events))
}

func serviceAuditReportError(ctx context.Context, status int, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	// permanent status classification survives a missing or malformed problem
	// body. transport errors and response bytes never enter returned text.
	switch status {
	case 400, 401, 403, 404, 409, 410, 413:
		return serviceaudit.ErrRejected
	}
	if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrStatusConflict) {
		return serviceaudit.ErrRejected
	}
	var problem *ProblemError
	if errors.As(err, &problem) {
		switch problem.Status {
		case 400, 401, 403, 404, 409, 410, 413:
			return serviceaudit.ErrRejected
		}
	}
	return errors.New("publisher service audit report failed")
}
