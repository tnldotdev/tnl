// Package emaildelivery sends typed email jobs without owning templates or SMTP.
package emaildelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type Store interface {
	ClaimInvitationEmail(context.Context, string, time.Time) (controlstate.EmailDelivery, error)
	FinishInvitationEmail(context.Context, controlstate.EmailDelivery, int, time.Time) error
}

type Worker struct {
	store  Store
	url    string
	token  string
	owner  string
	client *http.Client
}

func New(store Store, origin, token string, client *http.Client) (*Worker, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || token == "" || store == nil {
		return nil, errors.New("emaildelivery: invalid receiver configuration")
	}
	owner, err := opaqueid.New("ew_")
	if err != nil {
		return nil, err
	}
	configured := http.Client{}
	if client != nil {
		configured = *client
	}
	configured.Timeout = 10 * time.Second
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Worker{store: store, url: origin + "/api/internal/tnl/emails", token: token, owner: owner, client: &configured}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	return workerloop.Run(ctx, workerloop.Config{OperationTimeout: 30 * time.Second, IdleInterval: 5 * time.Second, Process: w.Process,
		OnError: func(error) {
			if ctx.Err() == nil {
				log.Print("email delivery iteration failed; check database and receiver health")
			}
		}})
}

func (w *Worker) Process(ctx context.Context) (bool, error) {
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
	request.Header.Set("Authorization", "Bearer "+w.token)
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
