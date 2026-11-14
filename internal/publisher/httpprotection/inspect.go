// package httpprotection inspects application requests for public URL and saved
// HTTP service publishers. it owns request buffers and a process-wide gate;
// callers prepare it once per run and close it after joining their requests.
// it depends on policy values, not either publication orchestrator.
package httpprotection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

// two inspections bound retained input without tying capacity to responses.
const concurrency = 2

var slots = make(chan struct{}, concurrency)

type Inspector struct {
	settings policy.Settings
	waf      coraza.WAF
	dir      string
	gate     chan struct{}
	blocks   *temporaryBlocks
}

// Result contains only allowlisted facts, never matched data or request headers.
type Result struct {
	Status  int
	RuleIDs []int
}

func New(settings policy.Settings) (*Inspector, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	p := &Inspector{settings: settings.Defaults(), gate: slots}
	p.settings.MaxBodyBytes = new(*p.settings.MaxBodyBytes)
	if p.settings.WAF == policy.Off {
		return p, nil
	}
	dir, err := os.MkdirTemp("", "tnl-waf-")
	if err != nil {
		return nil, fmt.Errorf("prepare private HTTP inspection storage: %w", err)
	}
	p.dir = dir
	mode := "On"
	if p.settings.WAF == policy.Detect {
		mode = "DetectionOnly"
	}
	directives := fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecArgumentsLimit 1000
SecRequestBodyJsonDepthLimit 64
SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0
SecTmpDir "%s"
SecUploadDir "%s"
SecUploadKeepFiles Off
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/(?:[a-z0-9.-]+\+)?json(?:\s*;|$)" "id:200001,phase:1,pass,nolog,t:none,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,deny,status:400,nolog,t:none"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,deny,status:400,nolog,t:none"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200004,phase:2,deny,status:413,nolog,t:none"
Include @crs-setup.conf.example
SecAction "id:100000,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=GET HEAD POST PUT PATCH DELETE OPTIONS',setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.paranoia_level=1',setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |application/json| |text/plain| |application/octet-stream|',setvar:'tx.restricted_headers_basic=/proxy/ /lock-token/ /if/ /x-http-method-override/ /x-http-method/ /x-method-override/ /x-middleware-subrequest/'"
`, mode, *p.settings.MaxBodyBytes+1, min(131072, *p.settings.MaxBodyBytes), directiveString(dir), directiveString(dir))
	// content types without a structured processor remain opaque. the adapter
	// rejects content encodings, rather than claiming compressed inspection.
	directives += `
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/[a-z0-9.-]+\+json(?:\s*;|$)" "id:100001,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=920420"
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^(?:(?:text|image|audio|video)/[a-z0-9.+-]+|application/(?:octet-stream|pdf|zip))(?:\s*;|$)" "id:100002,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=920420"
`
	for index, e := range p.settings.Exclusions {
		action := fmt.Sprintf("ctl:ruleRemoveById=%d", e.RuleID)
		if e.Parameter != "" {
			action = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", e.RuleID, e.Parameter)
		}
		// hex escapes make every configured path a literal, not rule syntax.
		var literal strings.Builder
		for _, b := range []byte(e.Path) {
			fmt.Fprintf(&literal, `\x%02x`, b)
		}
		directives += fmt.Sprintf("SecRule REQUEST_URI_RAW \"@rx ^%s(?:\\?|$)\" \"id:%d,phase:1,pass,nolog,t:none,%s\"\n", literal.String(), 110000+index, action)
	}
	// request-only CRS: never load response or logging rules.
	directives += "Include @owasp_crs/REQUEST-*.conf\n"
	// opaque formats must not be misparsed as URL-encoded arguments.
	directives += "SecRuleRemoveById 901340\n"
	p.waf, err = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDebugLogger(debuglog.Noop()).WithDirectives(directives))
	if err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("prepare managed HTTP protection: %w", err)
	}
	return p, nil
}

func directiveString(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func (p *Inspector) Close() error {
	if p == nil {
		return nil
	}
	p.blocks.close()
	var result error
	if p.waf != nil {
		// the pinned engine owns process-wide compiled-pattern cache entries.
		result = p.waf.(experimental.WAFCloser).Close()
	}
	if p.dir == "" {
		return result
	}
	// transactions remove their files first. do not conceal leaked buffers.
	err := os.Remove(p.dir)
	if os.IsNotExist(err) {
		err = nil
	}
	return errors.Join(result, err)
}

// Inspect returns an owned request and cleanup even on failure. the caller
// defers cleanup as a fallback; body EOF/Close normally releases it much earlier.
func (p *Inspector) Inspect(r *http.Request) (*http.Request, func(), Result) {
	nothing := func() {}
	if p == nil || p.waf == nil {
		return r, nothing, Result{}
	}
	if p.settings.BlocksSources() && p.blocks == nil {
		return r, nothing, Result{Status: http.StatusServiceUnavailable}
	}
	if r.Context().Err() != nil {
		return r, nothing, Result{Status: http.StatusServiceUnavailable}
	}
	select {
	case p.gate <- struct{}{}:
	default:
		return r, nothing, Result{Status: http.StatusServiceUnavailable}
	}
	tx := p.waf.NewTransaction()
	var once sync.Once
	closeTX := func() { once.Do(func() { _ = tx.Close(); <-p.gate }) }
	retained := false
	defer func() {
		if !retained {
			closeTX()
		}
	}()
	fail := func(status int) (*http.Request, func(), Result) {
		result := Result{Status: status, RuleIDs: matchedIDs(tx)}
		closeTX()
		return r, nothing, result
	}
	if r.ContentLength > int64(*p.settings.MaxBodyBytes) {
		return fail(http.StatusRequestEntityTooLarge)
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") && p.settings.WAF == policy.Block {
		return fail(http.StatusUnsupportedMediaType)
	}
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	sourcePort, _ := strconv.Atoi(port)
	tx.ProcessConnection(host, sourcePort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	tx.SetServerName(r.Host)
	tx.AddRequestHeader("Host", r.Host)
	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
	for _, encoding := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", encoding)
	}
	if r.ContentLength >= 0 && r.Header.Get("Content-Length") == "" {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return fail(interruptionStatus(interruption))
	}
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	size := 0
	if hasBody {
		// cap independently: Coraza detection-only mode permits partial bodies.
		interruption, n, err := tx.ReadRequestBodyFrom(io.LimitReader(r.Body, int64(*p.settings.MaxBodyBytes)+1))
		size = n
		if n > *p.settings.MaxBodyBytes || interruption != nil && interruption.Status == 413 {
			return fail(http.StatusRequestEntityTooLarge)
		}
		if err != nil {
			return fail(http.StatusBadRequest)
		}
		if interruption != nil {
			return fail(interruptionStatus(interruption))
		}
	}
	interruption, err := tx.ProcessRequestBody()
	// safety failures are explicit even in detection-only mode. never forward
	// a truncated argument collection as if the whole body was inspected.
	for _, match := range tx.MatchedRules() {
		switch match.Rule().ID() {
		case 200002, 200003:
			return fail(http.StatusBadRequest)
		case 200004:
			return fail(http.StatusRequestEntityTooLarge)
		}
	}
	if err != nil {
		return fail(http.StatusBadRequest)
	} else if interruption != nil {
		return fail(interruptionStatus(interruption))
	}
	result := Result{RuleIDs: matchedIDs(tx)}
	if !hasBody || size == 0 {
		closeTX()
		return r, nothing, result
	}
	reader, err := tx.RequestBodyReader()
	if err != nil {
		return fail(http.StatusServiceUnavailable)
	}
	original := r.Body
	owned := &body{reader: reader, remaining: size, cleanup: closeTX}
	owned.mu.Lock()
	owned.stop = context.AfterFunc(r.Context(), func() { _ = owned.Close() })
	owned.mu.Unlock()
	r = r.Clone(r.Context())
	r.Body = owned
	// the incoming owner has consumed trailers; buffered forwarding must not
	// depend on another read from the already exhausted socket body.
	cleanup := func() { _ = owned.Close(); _ = original.Close() }
	retained = true
	return r, cleanup, result
}

type body struct {
	mu        sync.Mutex
	reader    io.Reader
	remaining int
	cleanup   func()
	stop      func() bool
	closed    bool
}

func (b *body) Read(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.EOF
	}
	n, err := b.reader.Read(data)
	b.remaining -= n
	if err != nil || b.remaining == 0 {
		b.close()
	}
	return n, err
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.close()
	return nil
}

func (b *body) close() {
	if !b.closed {
		b.closed = true
		if b.stop != nil {
			b.stop()
		}
		b.reader = nil
		b.cleanup()
	}
}

func matchedIDs(tx types.Transaction) []int {
	seen := make(map[int]bool)
	for _, match := range tx.MatchedRules() {
		id := match.Rule().ID()
		for _, tag := range match.Rule().Tags() {
			if strings.HasPrefix(tag, "attack-") {
				seen[id] = true
				break
			}
		}
	}
	ids := make([]int, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func interruptionStatus(i *types.Interruption) int {
	if i.Status == http.StatusBadRequest || i.Status == http.StatusRequestEntityTooLarge {
		return i.Status
	}
	return http.StatusForbidden
}

// source blocks also apply before reserved challenge preparation.
func (p *Inspector) AllowSource(w http.ResponseWriter, r *http.Request) bool {
	source, err := netip.ParseAddrPort(r.RemoteAddr)
	if p != nil && p.blocks != nil && (err != nil || p.blocks.blocked(source.Addr(), time.Now())) {
		w.Header().Set("Cache-Control", "no-store")
		diagnostic.WriteHTTP(w, r, diagnostic.HttpProtectionRejected, "")
		return false
	}
	return true
}

// Handler is only for the already authorized application boundary. reserved
// preparation endpoints must be handled by the caller before entering it.
func (p *Inspector) Handler(next http.Handler, observe func(Result)) http.Handler {
	return httpstream.Requests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, cleanup, result := r, func() {}, Result{}
		source, err := netip.ParseAddrPort(r.RemoteAddr)
		if p != nil && p.blocks != nil && (err != nil || p.blocks.blocked(source.Addr(), time.Now())) {
			result.Status = http.StatusForbidden
		} else {
			request, cleanup, result = p.Inspect(r)
			if p != nil && p.blocks != nil {
				p.blocks.reject(source.Addr(), result, time.Now())
			}
		}
		defer cleanup()
		if p != nil {
			observability.HTTPProtection(r.Context(), p.settings.WAF, result.Status, result.RuleIDs)
		}
		if observe != nil {
			observe(result)
		}
		if result.Status != 0 {
			w.Header().Set("Cache-Control", "no-store")
			if result.Status == http.StatusServiceUnavailable {
				w.Header().Set("Retry-After", "1")
			}
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			code := diagnostic.HttpProtectionRejected
			switch result.Status {
			case 400:
				code = diagnostic.HttpProtectionBodyInvalid
			case 413:
				code = diagnostic.HttpProtectionBodyTooLarge
			case 415:
				code = diagnostic.HttpProtectionEncodingUnsupported
			case 503:
				code = diagnostic.HttpProtectionUnavailable
			}
			diagnostic.WriteHTTP(w, r, code, "")
			return
		}
		next.ServeHTTP(w, request)
	}), httpstream.RequestBodyTimeout)
}
