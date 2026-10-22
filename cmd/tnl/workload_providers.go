package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/httpclient"
)

var readVercelWorkload = vercelWorkloadMetadata

func bindProviderWorkload(ctx context.Context, p config.Workload, previous controlstate.ProjectWorkload) (oidcauth.WorkloadTrust, error) {
	t := oidcauth.WorkloadTrust{Provider: p.Provider, Claims: map[string]string{}}
	switch p.Provider {
	case "vercel":
		if p.TeamSlug == "" || p.IssuerMode == "" {
			if previous.Provider == "vercel" && previous.Trust.Claims["owner_id"] == p.TeamID && previous.Trust.Claims["project_id"] == p.ProjectID {
				if p.TeamSlug == "" {
					p.TeamSlug = previous.Trust.Claims["owner"]
				}
				if p.IssuerMode == "" {
					p.IssuerMode = "team"
					if previous.Trust.Issuer == "https://oidc.vercel.com" {
						p.IssuerMode = "global"
					}
				}
			} else {
				slug, mode, err := readVercelWorkload(ctx, p.TeamID, p.ProjectID)
				if err != nil {
					return t, err
				}
				if p.TeamSlug != "" && p.TeamSlug != slug || p.IssuerMode != "" && p.IssuerMode != mode {
					return t, controlstate.ErrWorkloadBinding
				}
				p.TeamSlug, p.IssuerMode = slug, mode
			}
		}
		t.Issuer = "https://oidc.vercel.com"
		if p.IssuerMode == "team" {
			t.Issuer += "/" + p.TeamSlug
		}
		t.JWKSURL = t.Issuer + "/.well-known/jwks"
		t.Audience = "https://vercel.com/" + p.TeamSlug
		t.Claims = map[string]string{"owner": p.TeamSlug, "owner_id": p.TeamID, "project_id": p.ProjectID, "environment": p.Environment}
	case "fly":
		t.Issuer = "https://oidc.fly.io/" + p.Org
		t.JWKSURL = t.Issuer + "/.well-known/jwks"
		t.Audience = "https://fly.io/" + p.Org
		t.Claims = map[string]string{"org_name": p.Org, "org_id": p.OrgID, "app_name": p.App, "app_id": p.AppID}
		if p.MachineID != "" {
			t.Claims["machine_id"] = p.MachineID
		}
	case "oidc":
		t.Issuer, t.JWKSURL, t.Audience, t.Claims = p.Issuer, p.JWKSURL, p.Audience, p.Claims
	default:
		return t, controlstate.ErrWorkloadBinding
	}
	return t, nil
}

// trusted setup reads the documented API, never an unsigned token or runtime file.
func vercelWorkloadMetadata(ctx context.Context, team, project string) (slug, mode string, err error) {
	token := os.Getenv("VERCEL_TOKEN")
	if token == "" {
		return "", "", errors.New("set workload team_slug and issuer_mode from Vercel settings, or provide VERCEL_TOKEN during apply")
	}
	client := httpclient.NoRedirects(&http.Client{Timeout: 10 * time.Second})
	get := func(endpoint string, target any) error {
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.vercel.com"+endpoint, nil)
		if e != nil {
			return e
		}
		r.Header.Set("Authorization", "Bearer "+token)
		resp, e := client.Do(r)
		if e != nil {
			return e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return controlstate.ErrWorkloadBinding
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(target)
	}
	var p struct {
		ID        string `json:"id"`
		AccountID string `json:"accountId"`
		OIDC      struct {
			Enabled bool   `json:"enabled"`
			Mode    string `json:"issuerMode"`
		} `json:"oidcTokenConfig"`
	}
	if err = get("/v9/projects/"+url.PathEscape(project)+"?teamId="+url.QueryEscape(team), &p); err != nil {
		return
	}
	if p.ID != project || p.AccountID != team || !p.OIDC.Enabled || p.OIDC.Mode != "team" && p.OIDC.Mode != "global" {
		return "", "", controlstate.ErrWorkloadBinding
	}
	var t struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err = get("/v2/teams/"+url.PathEscape(team), &t); err != nil {
		return
	}
	if t.ID != team || !config.ExactWorkloadValue(t.Slug) {
		return "", "", controlstate.ErrWorkloadBinding
	}
	return t.Slug, p.OIDC.Mode, nil
}
