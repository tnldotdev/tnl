package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

func (a *appRuntime) publisherAuthConfig(ctx context.Context) (clientauth.Config, error) {
	resolver := newProjectMetadataResolver(a.state, a.project, strings.NewReader(""), io.Discard, "project publisher login")
	server, err := resolver.server(ctx, a.project.Config.Server)
	if err != nil {
		return clientauth.Config{}, err
	}
	return clientauth.Config{ServerEndpoint: server, State: a.state, Diagnostics: io.Discard, HTTPClient: a.authHTTP}, nil
}

func (a *appRuntime) publisherAuthHandler(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/login/start", func(w http.ResponseWriter, r *http.Request) {
		config, err := a.publisherAuthConfig(r.Context())
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		operation, err := clientauth.StartLogin(r.Context(), config)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, operation)
	})
	mux.HandleFunc("POST /v1/auth/login/wait", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID             string `json:"operation_id"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if err := privateprotocol.Decode(w, r, &request); err != nil || request.TimeoutSeconds < 1 || request.TimeoutSeconds > 600 {
			runtimeProblem(w, errors.New("invalid login operation or wait timeout"))
			return
		}
		config, err := a.publisherAuthConfig(r.Context())
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		operation, err := clientauth.WaitLogin(r.Context(), config, request.ID, time.Duration(request.TimeoutSeconds)*time.Second)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, operation)
	})
	for _, action := range []string{"inspect", "cancel"} {
		method := http.MethodGet
		if action == "cancel" {
			method = http.MethodDelete
		}
		mux.HandleFunc(method+" /v1/auth/login/{operation_id}", func(w http.ResponseWriter, r *http.Request) {
			config, err := a.publisherAuthConfig(r.Context())
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			var operation any
			if action == "cancel" {
				operation, err = clientauth.CancelLogin(r.Context(), config, r.PathValue("operation_id"))
			} else {
				operation, err = clientauth.InspectLogin(r.Context(), config, r.PathValue("operation_id"))
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			privateprotocol.Write(w, http.StatusOK, operation)
		})
	}
	mux.HandleFunc("POST /v1/auth/login/token", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Token string `json:"token"`
		}
		if err := privateprotocol.Decode(w, r, &request); err != nil {
			runtimeProblem(w, err)
			return
		}
		token, err := parseLoginInput([]byte(request.Token))
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		config, err := a.publisherAuthConfig(r.Context())
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		config.ForceLoginToken = true
		config.LoginToken = func() (credentials.LoginToken, error) { return token, nil }
		if _, err := clientauth.Login(r.Context(), config); err != nil {
			runtimeProblem(w, err)
			return
		}
		status, err := clientauth.Status(r.Context(), config, false)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, status)
	})
	mux.HandleFunc("GET /v1/auth/status", func(w http.ResponseWriter, r *http.Request) {
		config, err := a.publisherAuthConfig(r.Context())
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		status, err := clientauth.Status(r.Context(), config, r.URL.Query().Has("check"))
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, status)
	})
	mux.HandleFunc("POST /v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		config, err := a.publisherAuthConfig(r.Context())
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		if err := clientauth.Logout(r.Context(), config); err != nil {
			runtimeProblem(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
