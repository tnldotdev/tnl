package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func checkReady(ctx context.Context, port int) error {
	if port < 1 || port > 65535 {
		return failure.Wrap("select readiness port", failure.ServerCommandInvalid, errors.New("port must be between 1 and 65535"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/ready", nil)
	if err != nil {
		return failure.Wrap("prepare readiness request", failure.ServerNotReady, err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return failure.Wrap("probe local readiness", failure.ServerNotReady, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return failure.Wrap("probe local readiness", failure.ServerNotReady, errors.New("readiness endpoint did not return 204"))
	}
	return nil
}
