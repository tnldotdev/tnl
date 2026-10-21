package publisher

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/httpstream"
	"github.com/tnldotdev/tnl/internal/kubernetes"
	"github.com/tnldotdev/tnl/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

// KubernetesLimits bounds requests without imposing a short idle timeout on an
// active watch or upgrade. the HTTP admission budget is shared across the run.
type KubernetesLimits struct {
	RequestDuration time.Duration
	StreamDuration  time.Duration
}

func (l KubernetesLimits) defaults() KubernetesLimits {
	if l.RequestDuration == 0 {
		l.RequestDuration = 2 * time.Minute
	}
	if l.StreamDuration == 0 {
		l.StreamDuration = time.Hour
	}
	return l
}

func (s ManagedStream) forwardKubernetes(ctx context.Context, client *tls.Conn, target ManagedHTTPTarget, initial ManagedVisitorDecision) error {
	limits := s.Kubernetes.defaults()
	if limits.RequestDuration < time.Millisecond || limits.RequestDuration > 10*time.Minute || limits.StreamDuration < time.Millisecond || limits.StreamDuration > 24*time.Hour {
		return ErrManagedTLS
	}
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.guardVisitor(live, client, nil, initial) }()
	defer func() { cancel(); <-done }()
	return httpstream.Serve(live, client, &url.URL{Scheme: "https", Host: target.Address}, func(ctx context.Context) (net.Conn, error) {
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
			if r.Host != s.Authority && s.Authority != "" || r.URL.IsAbs() || r.URL.Host != "" || strings.HasPrefix(r.URL.Path, "/__tnl/") || r.Method == http.MethodConnect {
				managedHTTPDenied(w, http.StatusMisdirectedRequest)
				return
			}
			check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			check, authDone := observability.PublisherOperation(check, "visitor_authorization")
			decision, err := s.Visitor.authorize(check, client.ConnectionState())
			observability.PublisherAuthorization(check, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
			authDone(managedAuthorizationError(decision, err))
			cancel()
			if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
				managedHTTPDenied(w, managedHTTPDecisionStatus(err))
				return
			}
			release, ok := s.HTTPRequests.admit(w, r)
			if !ok {
				return
			}
			defer release()
			class := kubernetes.Classify(r)
			trace.SpanFromContext(r.Context()).SetAttributes(observability.KubernetesVerb.String(class.Verb), observability.KubernetesAPIGroup.String(class.APIGroup), observability.KubernetesResource.String(class.Resource), observability.KubernetesSubresource.String(class.Subresource))
			duration := limits.RequestDuration
			if class.LongRunning {
				duration = limits.StreamDuration
			}
			// close the whole selected stream on expiry, including hijacked upgrades.
			// net/http request cancellation alone does not own a hijacked connection.
			timer := time.AfterFunc(duration, func() { _ = client.Close() })
			defer timer.Stop()
			r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
			r.Header.Del("Tnl-Access-Token")
			r.Header.Del(shareAccessHeaderName)
			r.Header.Del("Cookie")
			r.Header.Del("Forwarded")
			r.Header.Del("X-Real-IP")
			for key := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
					r.Header.Del(key)
				}
			}
			// Authorization belongs to the cluster, independently of tnl admission.
			next.ServeHTTP(w, r)
		})
	})
}
