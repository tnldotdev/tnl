package oidctest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// Approve completes the development provider's real browser form, OIDC callback,
// and explicit control approval. it has no access to control's private tokens.
func Approve(ctx context.Context, base *http.Client, approvalURL string) error {
	client := *base
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = nil
	get, err := http.NewRequestWithContext(ctx, "GET", approvalURL, nil)
	if err != nil {
		return err
	}
	q := get.URL.Query()
	q.Set("team", q.Get("team"))
	get.URL.RawQuery = q.Encode()
	response, err := client.Do(get)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || response.Request.URL.Path != "/authorize" {
		return errors.New("development provider authorization page missing")
	}
	endpoint := *response.Request.URL
	fields := endpoint.Query()
	endpoint.RawQuery = ""
	post, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), strings.NewReader(fields.Encode()))
	if err != nil {
		return err
	}
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(post)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || response.Request.URL.Path != "/v1/auth/device/callback" {
		return errors.New("control device confirmation missing")
	}
	approval, err := url.Parse(approvalURL)
	if err != nil {
		return err
	}
	var binding string
	for _, cookie := range client.Jar.Cookies(approval) {
		if cookie.Name == "__Host-tnl-device" {
			binding = cookie.Value
		}
	}
	form := url.Values{"code": {approval.Query().Get("code")}, "binding": {binding}}
	approval.RawQuery = ""
	post, err = http.NewRequestWithContext(ctx, "POST", approval.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(post)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 {
		return errors.New("control device approval failed")
	}
	return nil
}
