// package emaildelivery sends queued invitation emails to a mailer.
package emaildelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/operatorlog"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type Store interface {
	ClaimInvitationEmail(context.Context, string, time.Time) (controlstate.EmailDelivery, error)
	FinishInvitationEmail(context.Context, controlstate.EmailDelivery, int, time.Time) error
}

type Worker struct {
	store  Store
	url    string
	secret string
	owner  string
	client *http.Client
}

func New(store Store, origin, secret string, client *http.Client) (*Worker, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || secret == "" || store == nil {
		return nil, failure.Wrap("configure invitation email worker", failure.ServerEmailConfigInvalid,
			errors.New("invalid email receiver configuration"))
	}
	owner, err := opaqueid.New(opaqueid.EmailWorkerPrefix)
	if err != nil {
		return nil, failure.Wrap("create invitation email worker ID", failure.ServerEmailDeliveryFailed, err)
	}
	configured := http.Client{}
	if client != nil {
		configured = *client
	}
	configured.Timeout = 10 * time.Second
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Worker{store: store, url: origin + "/api/internal/tnl/emails", secret: secret, owner: owner, client: &configured}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	return workerloop.Run(ctx, workerloop.Config{OperationTimeout: 30 * time.Second, IdleInterval: 5 * time.Second, Process: w.Process,
		OnError: func(err error) {
			if ctx.Err() == nil {
				operatorlog.Report("process invitation email", failure.ServerEmailDeliveryFailed, "", err)
			}
		}})
}

func (w *Worker) Process(ctx context.Context) (more bool, retErr error) {
	defer func() {
		if _, classified := failure.ReasonOf(retErr); retErr != nil && !classified {
			retErr = failure.Wrap("process invitation email", failure.ServerEmailDeliveryFailed, retErr)
		}
	}()
	delivery, err := w.store.ClaimInvitationEmail(ctx, w.owner, time.Now())
	if err != nil || delivery.ID == "" {
		return false, err
	}
	body, err := json.Marshal(delivery.Payload)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+w.secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", delivery.ID)
	status := 0
	if response, err := w.client.Do(request); err == nil {
		status = response.StatusCode
		response.Body.Close()
	}
	// persist retry state without logging transport errors that can include secrets.
	err = w.store.FinishInvitationEmail(ctx, delivery, status, time.Now())
	return err == nil, err
}
