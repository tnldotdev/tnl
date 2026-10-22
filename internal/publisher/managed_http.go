package publisher

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpstream"
	"github.com/tnldotdev/tnl/internal/httpsubject"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ManagedHTTPControl interface {
	ControlURL() string
	AuthorizeManagedHTTPVisitor(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error)
	RedeemManagedBrowserHandoff(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckManagedBrowserSession(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeManagedBrowserSession(context.Context, string, string, credentials.ManagedRunToken, controlv1.ManagedBrowserRequest) error
}

// ManagedHTTP is built for each trusted forwarding header, never from HTTP
// headers. all requests use the same selected run and one upstream connection.
type ManagedHTTP struct {
	Control  ManagedHTTPControl
	Subject  httpsubject.Subject
	RunID    string
	Number   int64
	Token    credentials.ManagedRunToken
	Hostname string
	Port     uint16
	Header   tunnelv1.PrivateForwardingHeader
	Requests *ManagedHTTPRequestLimits
}

func (f ManagedHTTP) Forward(ctx context.Context, client *tls.Conn, target ManagedHTTPTarget) error {
	h := f.Header
	if f.Control == nil || f.Subject.Kind != httpsubject.ManagedService || !f.Subject.Valid() || h.Direct == nil || h.Connector != nil || h.PrivateServiceID != f.Subject.ID || h.PrivateRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.Direct.DestinationPort != f.Port || f.Port < 1024 || h.Validate() != nil {
		return ErrManagedTLS
	}
	controlURL, err := url.Parse(f.Control.ControlURL())
	if err != nil || controlURL.Scheme != "https" || controlURL.Host == "" || controlURL.User != nil || controlURL.RawQuery != "" || controlURL.Fragment != "" {
		return ErrManagedTLS
	}
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	guard := newManagedHTTPGuard(f, client)
	done := make(chan struct{})
	go func() { defer close(done); guard.run(live) }()
	defer func() { cancel(); <-done }()
	authority := net.JoinHostPort(f.Hostname, strconv.Itoa(int(f.Port)))
	// the browser UI's public-run credential is unused; the adapter retains the
	// managed authority and never converts it to a public URL publish run token.
	browser := &browserAccess{subject: f.Subject, client: managedBrowserClient{f}, runID: f.RunID, version: uint64(f.Number), controlURL: strings.TrimSuffix(f.Control.ControlURL(), "/")}
	scheme := "http"
	if target.Transport.TLS != nil {
		scheme = "https"
	}
	return httpstream.Serve(live, client, &url.URL{Scheme: scheme, Host: target.Address}, func(ctx context.Context) (net.Conn, error) {
		setup, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, err := observability.DialTarget(setup, "tcp", target.Address)
		if err != nil {
			return nil, err
		}
		secured, err := target.Transport.Secure(setup, conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return secured, nil
	}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// consume the reserved header even for denied and internal dispatch.
			credential, credentialErr := managedHTTPCredential(r, client.ConnectionState())
			w.Header().Set("Cache-Control", "no-store")
			if r.Host != authority || r.URL.IsAbs() || r.URL.Host != "" {
				managedHTTPDenied(w, http.StatusMisdirectedRequest)
				return
			}
			// authentication endpoints cannot consume unbounded bodies or promote
			// application capacity. ingress bounds their bytes and total lifetime.
			if strings.HasPrefix(r.URL.Path, "/__tnl/") {
				if credentialErr != nil || credential.Kind == "workload" || workloadClientCertificate(client.ConnectionState()) {
					managedHTTPDenied(w, http.StatusForbidden)
					return
				}
				if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" {
					managedHTTPDenied(w, http.StatusBadRequest)
					return
				}
				if browser.handle(w, r, false) {
					return
				}
				if sharePath(r.URL.Path) && r.Method == http.MethodGet {
					f.share(w, r, guard)
					return
				}
				http.NotFound(w, r)
				return
			}
			if credentialErr != nil {
				managedHTTPDenied(w, http.StatusForbidden)
				return
			}
			check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			decision, err := guard.authorize(check, credential)
			cancel()
			if err != nil || !decision.Allowed || !decision.Admitted || !decision.ValidUntil.After(time.Now()) {
				if err == nil && credential.Kind == "none" && browser.redirectRestricted(w, r) {
					return
				}
				managedHTTPDenied(w, managedHTTPDecisionStatus(err))
				return
			}
			// internal credentials and spoofed forwarding identity never reach the
			// application. the selected target transport owns target TLS trust.
			release, ok := f.Requests.admit(w, r)
			if !ok {
				return
			}
			defer release()
			r = stripTnlCookies(r)
			r.Header.Del(shareAccessHeaderName)
			r.Header.Del("Tnl-Access-Token")
			r.Header.Del("Forwarded")
			r.Header.Del("X-Real-IP")
			for key := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
					r.Header.Del(key)
				}
			}
			next.ServeHTTP(w, r)
		})
	})
}

func managedHTTPDenied(w http.ResponseWriter, status int) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	message := "managed HTTP access denied"
	if status == http.StatusServiceUnavailable {
		message = "managed HTTP authorization is unavailable; retry"
	}
	http.Error(w, message, status)
}

func managedHTTPDecisionStatus(err error) int {
	if err == nil || errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrStatusConflict) {
		return http.StatusForbidden
	}
	var problem *controlclient.ProblemError
	if errors.As(err, &problem) && (problem.Status == 401 || problem.Status == 403 || problem.Status == 404 || problem.Status == 409) {
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}

func managedHTTPCredential(r *http.Request, state tls.ConnectionState) (controlv1.ManagedHTTPCredential, error) {
	// a workload certificate is the final visitor credential, including after
	// revocation. browser cookies and HTTP tokens cannot replace that subject.
	// this URI selects validation only; control still verifies the issuer/scope.
	if workloadClientCertificate(state) {
		der := state.PeerCertificates[0].Raw
		if len(der) == 0 || len(der) > 16<<10 {
			return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
		}
		return controlv1.ManagedHTTPCredential{Kind: "certificate", Certificate: &der}, nil
	}
	// a supplied explicit credential is final, even when invalid. application
	// Authorization remains application-owned; tnl uses scoped dedicated headers.
	for _, header := range []struct{ name, kind string }{{"Tnl-Access-Token", "token"}, {shareAccessHeaderName, "share"}} {
		values, present := r.Header[http.CanonicalHeaderKey(header.name)]
		if present {
			if len(values) != 1 || !validManagedGrantSecret(values[0]) {
				return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
			}
			return controlv1.ManagedHTTPCredential{Kind: controlv1.ManagedHTTPCredentialKind(header.kind), Secret: &values[0]}, nil
		}
	}
	for _, cookie := range []struct{ name, kind string }{{browserAccessCookieName, "browser"}, {shareCookieName, "share"}} {
		values := r.CookiesNamed(cookie.name)
		if suppliedCookieCount(r, cookie.name) != len(values) {
			return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
		}
		if len(values) > 0 {
			if len(values) != 1 {
				return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
			}
			secret := values[0].Value
			if cookie.kind == "browser" {
				raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
				if err != nil || len(raw) != 32 {
					return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
				}
			} else if !validManagedGrantSecret(secret) {
				return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
			}
			return controlv1.ManagedHTTPCredential{Kind: controlv1.ManagedHTTPCredentialKind(cookie.kind), Secret: &secret}, nil
		}
	}
	if len(state.PeerCertificates) > 0 {
		der := state.PeerCertificates[0].Raw
		if len(der) > 16<<10 {
			return controlv1.ManagedHTTPCredential{}, ErrManagedTLS
		}
		return controlv1.ManagedHTTPCredential{Kind: "certificate", Certificate: &der}, nil
	}
	return controlv1.ManagedHTTPCredential{Kind: "none"}, nil
}

func workloadClientCertificate(state tls.ConnectionState) bool {
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return false
	}
	for _, uri := range state.PeerCertificates[0].URIs {
		if uri.Scheme == "tnl" && uri.Host == "workload-client" {
			return true
		}
	}
	return false
}

// net/http omits malformed cookies during parsing. a supplied tnl credential
// must still fail closed instead of falling through to certificate admission.
func suppliedCookieCount(r *http.Request, name string) int {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			key, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(key) == name {
				count++
			}
		}
	}
	return count
}

func validManagedGrantSecret(value string) bool {
	id, raw, ok := strings.Cut(value, ".")
	if !ok || !opaqueid.Valid(id, "mhg_") {
		return false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(secret) == 32
}

func (f ManagedHTTP) authorize(ctx context.Context, credential controlv1.ManagedHTTPCredential) (controlv1.ServiceClientCertificateDecision, error) {
	ctx = observability.WithPublisherProtocol(ctx, "http")
	ctx, finish := observability.PublisherOperation(ctx, "visitor_authorization")
	input := controlv1.ManagedHTTPVisitorRequest{RunNumber: f.Number, VisitorConnectionId: f.Header.VisitorConnectionID, SourceIp: f.Header.SourceIP, DestinationPort: int(f.Port), Credential: credential}
	for {
		decision, err := f.Control.AuthorizeManagedHTTPVisitor(ctx, f.Subject.ID, f.RunID, f.Token, input)
		observability.PublisherAuthorization(ctx, decision.Allowed, decision.Admitted, err)
		if err != nil || !decision.Allowed || decision.Admitted {
			finish(managedAuthorizationError(ManagedVisitorDecision{Allowed: decision.Allowed && decision.Admitted, ValidUntil: decision.ValidUntil}, err))
			return decision, err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			finish(context.Cause(ctx))
			return controlv1.ServiceClientCertificateDecision{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (f ManagedHTTP) share(w http.ResponseWriter, r *http.Request, guard *managedHTTPGuard) {
	secret := strings.TrimPrefix(r.URL.Path, "/__tnl/share/")
	if !validManagedGrantSecret(secret) {
		managedHTTPDenied(w, 403)
		return
	}
	// validation uses the exact admission too. no application bytes are sent by
	// redemption; the following request must independently present the cookie.
	check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	decision, err := guard.authorize(check, controlv1.ManagedHTTPCredential{Kind: "share", Secret: &secret})
	if err != nil || !decision.Allowed || !decision.Admitted {
		managedHTTPDenied(w, managedHTTPDecisionStatus(err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// adapt the shared browser UI without treating a managed ID as a public URL ID.
type managedBrowserClient struct{ frontend ManagedHTTP }

func (a managedBrowserClient) request(run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.ManagedBrowserRequest, error) {
	f := a.frontend
	if run != f.RunID || number != uint64(f.Number) || token != "" {
		return controlv1.ManagedBrowserRequest{}, ErrManagedTLS
	}
	return controlv1.ManagedBrowserRequest{RunNumber: f.Number, Secret: secret}, nil
}
func (a managedBrowserClient) RedeemBrowserHandoff(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
	}
	f := a.frontend
	return f.Control.RedeemManagedBrowserHandoff(ctx, f.Subject.ID, f.RunID, f.Token, input)
}
func (a managedBrowserClient) CheckBrowserAccess(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	f := a.frontend
	return f.Control.CheckManagedBrowserSession(ctx, f.Subject.ID, f.RunID, f.Token, input)
}
func (a managedBrowserClient) RevokeBrowserAccess(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) error {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return err
	}
	f := a.frontend
	return f.Control.RevokeManagedBrowserSession(ctx, f.Subject.ID, f.RunID, f.Token, input)
}

var _ ManagedHTTPFrontend = ManagedHTTP{}
