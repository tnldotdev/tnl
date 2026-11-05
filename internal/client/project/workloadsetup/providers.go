package workloadsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/sys/unix"
)

func environment(name string) string { return os.Getenv(name) }

func commandOutput(ctx context.Context, directory, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	command.WaitDelay = time.Second
	var output boundedOutput
	command.Stdout = &output
	err := command.Run()
	if err != nil {
		return nil, errors.Join(ErrBinding, err)
	}
	return output.buffer.Bytes(), nil
}

type boundedOutput struct{ buffer bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.buffer.Len()+len(data) > 2<<20 {
		return 0, ErrBinding
	}
	return b.buffer.Write(data)
}

func (r resolver) bindProvider(ctx context.Context, o Options, p config.Workload, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadProvider(p.Provider()), Claims: map[string]string{}}
	switch p.Provider() {
	case "vercel":
		return r.vercel(ctx, o.Directory, p.Vercel, previous)
	case "fly":
		return r.fly(ctx, o.Directory, o.Server, p.Fly, previous)
	case "oidc":
		t.Issuer, t.JwksUrl, t.Audience, t.Claims = p.OIDC.Issuer, p.OIDC.JWKSURL, p.TokenAudience(o.Server), p.OIDC.Claims
		if t.JwksUrl == "" {
			if previous.Provider == t.Provider && previous.Trust.Issuer == t.Issuer && previous.Trust.JwksUrl != "" {
				t.JwksUrl = previous.Trust.JwksUrl
			} else {
				var document struct {
					Issuer string `json:"issuer"`
					Keys   string `json:"jwks_uri"`
				}
				if err := r.get(ctx, strings.TrimSuffix(t.Issuer, "/")+"/.well-known/openid-configuration", "", &document); err != nil {
					return t, err
				}
				if document.Issuer != t.Issuer || !config.WorkloadHTTPS(document.Keys) {
					return t, ErrBinding
				}
				t.JwksUrl = document.Keys
			}
		}
		return t, nil
	default:
		return t, ErrBinding
	}
}

func (r resolver) vercel(ctx context.Context, directory string, v *config.WorkloadVercel, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadVercel}
	old := previous.Trust
	if previous.Provider == t.Provider && old.Claims["project"] != "" && (v.Project == "" || v.Project == old.Claims["project"]) && (v.Team == "" || v.Team == old.Claims["owner"]) {
		t = old
		t.Claims = cloneClaims(old.Claims)
		t.Claims["environment"] = v.Environment
		return t, nil
	}
	project, team := v.Project, v.Team
	if project == "" {
		var link struct {
			ProjectID string `json:"projectId"`
			OrgID     string `json:"orgId"`
		}
		if err := readProjectJSON(filepath.Join(directory, ".vercel", "project.json"), &link); err != nil {
			return t, errors.Join(ErrVercelProject, err)
		}
		project = link.ProjectID
		if team == "" {
			team = link.OrgID
		}
	}
	if project == "" {
		return t, ErrBinding
	}
	token := r.getenv("VERCEL_TOKEN")
	if token == "" {
		return t, ErrVercelAuthentication
	}
	query := url.Values{}
	if strings.HasPrefix(team, "team_") {
		query.Set("teamId", team)
	} else if team != "" {
		query.Set("slug", team)
	}
	var metadata struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AccountID string `json:"accountId"`
		OIDC      struct {
			Enabled bool   `json:"enabled"`
			Mode    string `json:"issuerMode"`
		} `json:"oidcTokenConfig"`
	}
	if err := r.get(ctx, "https://api.vercel.com/v9/projects/"+url.PathEscape(project)+"?"+query.Encode(), token, &metadata); err != nil {
		return t, err
	}
	if !strings.HasPrefix(metadata.ID, "prj_") || !strings.HasPrefix(metadata.AccountID, "team_") || !naming.ValidAuthorityLabel(metadata.Name) || !metadata.OIDC.Enabled || metadata.OIDC.Mode != "team" && metadata.OIDC.Mode != "global" {
		return t, ErrBinding
	}
	if v.Project != "" && v.Project != metadata.Name {
		return t, ErrBinding
	}
	if strings.HasPrefix(project, "prj_") && metadata.ID != project {
		return t, ErrBinding
	}
	if strings.HasPrefix(team, "team_") && metadata.AccountID != team {
		return t, ErrBinding
	}
	if previous.Provider == t.Provider && (old.Claims["project_id"] != metadata.ID || old.Claims["owner_id"] != metadata.AccountID) {
		return t, ErrRebinding
	}
	var owner struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := r.get(ctx, "https://api.vercel.com/v2/teams/"+url.PathEscape(metadata.AccountID), token, &owner); err != nil {
		return t, err
	}
	if owner.ID != metadata.AccountID || !naming.ValidAuthorityLabel(owner.Slug) || v.Team != "" && v.Team != owner.Slug {
		return t, ErrBinding
	}
	t.Issuer = "https://oidc.vercel.com"
	if metadata.OIDC.Mode == "team" {
		t.Issuer += "/" + owner.Slug
	}
	t.JwksUrl, t.Audience = t.Issuer+"/.well-known/jwks", "https://vercel.com/"+owner.Slug
	t.Claims = map[string]string{"owner": owner.Slug, "owner_id": owner.ID, "project": metadata.Name, "project_id": metadata.ID, "environment": v.Environment}
	return t, nil
}

func (r resolver) fly(ctx context.Context, directory, server string, f *config.WorkloadFly, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadFly}
	app := f.App
	if app == "" {
		output, err := r.run(ctx, directory, "flyctl", "config", "show", "--local")
		if err != nil {
			return t, err
		}
		var local struct {
			App string `json:"app"`
		}
		if json.Unmarshal(output, &local) != nil {
			return t, ErrBinding
		}
		app = local.App
	}
	if !naming.ValidAuthorityLabel(app) {
		return t, ErrBinding
	}
	old := previous.Trust
	if previous.Provider == t.Provider && old.Claims["app_name"] == app && (f.Org == "" || old.Claims["org_name"] == f.Org) {
		t = old
		t.Audience, t.Claims = server, cloneClaims(old.Claims)
		delete(t.Claims, "machine_id")
		if f.MachineID != "" {
			t.Claims["machine_id"] = f.MachineID
		}
		return t, nil
	}
	token := r.getenv("FLY_API_TOKEN")
	if token == "" {
		output, err := r.run(ctx, directory, "flyctl", "auth", "token")
		if err != nil {
			return t, err
		}
		token = strings.TrimSpace(string(output))
	}
	if token == "" {
		return t, ErrBinding
	}
	body, err := json.Marshal(map[string]any{"query": `query($app: String!) { app(name: $app) { name internalNumericId organization { slug internalNumericId } } }`, "variables": map[string]string{"app": app}})
	if err != nil {
		return t, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.fly.io/graphql", bytes.NewReader(body))
	if err != nil {
		return t, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	var response struct {
		Errors []json.RawMessage `json:"errors"`
		Data   struct {
			App struct {
				Name string      `json:"name"`
				ID   json.Number `json:"internalNumericId"`
				Org  struct {
					Slug string      `json:"slug"`
					ID   json.Number `json:"internalNumericId"`
				} `json:"organization"`
			} `json:"app"`
		} `json:"data"`
	}
	if err = r.do(request, &response); err != nil {
		return t, err
	}
	a := response.Data.App
	if len(response.Errors) != 0 || a.Name != app || !naming.ValidAuthorityLabel(a.Org.Slug) || !positiveID(a.ID) || !positiveID(a.Org.ID) || f.Org != "" && a.Org.Slug != f.Org {
		return t, ErrBinding
	}
	if previous.Provider == t.Provider && (old.Claims["app_id"] != a.ID.String() || old.Claims["org_id"] != a.Org.ID.String()) {
		return t, ErrRebinding
	}
	t.Issuer = "https://oidc.fly.io/" + a.Org.Slug
	t.JwksUrl, t.Audience = t.Issuer+"/.well-known/jwks", server
	t.Claims = map[string]string{"org_name": a.Org.Slug, "org_id": a.Org.ID.String(), "app_name": a.Name, "app_id": a.ID.String()}
	if f.MachineID != "" {
		t.Claims["machine_id"] = f.MachineID
	}
	return t, nil
}

func positiveID(id json.Number) bool {
	value, err := strconv.ParseUint(id.String(), 10, 64)
	return err == nil && value > 0
}

func cloneClaims(claims map[string]string) map[string]string {
	result := make(map[string]string, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result
}

func readProjectJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return ErrBinding
	}
	return decodeJSON(file, value)
}

func (r resolver) get(ctx context.Context, endpoint, token string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return r.do(request, target)
}

func (r resolver) do(request *http.Request, target any) error {
	response, err := r.client.Do(request)
	if err != nil {
		return errors.Join(ErrBinding, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrBinding
	}
	return decodeJSON(response.Body, target)
}

func decodeJSON(reader io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
	if err != nil {
		return errors.Join(ErrBinding, err)
	}
	if len(data) > 2<<20 || json.Unmarshal(data, target) != nil {
		return ErrBinding
	}
	return nil
}
