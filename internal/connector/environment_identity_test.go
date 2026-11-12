package connector

import (
	"os"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"sync/atomic"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func environmentRefreshRequest(f *identityRefreshFixture) connectorruntime.EnvironmentStart {
	return connectorruntime.EnvironmentStart{Schema:1,Source:authorityv1.IdentitySourceSelection{Kind:"oidc",MachineId:"mci_0123456789ABCDEFGHIJKL"},Selection:connectorruntime.EnvironmentSelection{Environment:f.environment,PermissionID:"mwp_0123456789ABCDEFGHIJKL",Services:map[string]string{"db":"postgres"}}}
}

func TestEnvironmentNativeFileAcquisitionRefreshesIdleOwner(t *testing.T) {
	f:=newIdentityRefreshFixture(t)
	request:=environmentRefreshRequest(f)
	f.backend.scope.Environment=&request.Selection
	f.backend.environmentSource=request.Source
	f.backend.directory=t.TempDir()
	file:=filepath.Join(f.backend.directory,"identity.jwt")
	if err:=os.WriteFile(file,[]byte("fresh.private.jwt"),0o600);err!=nil{t.Fatal(err)}
	request.Acquisition=&workload.Acquisition{Method:"token-file",TokenFile:file}
	if err:=f.backend.configureEnvironmentAcquisition(request);err!=nil{t.Fatal(err)}
	if f.backend.refreshAssertion==nil {t.Fatal("native rotating file did not retain a background source")}
	f.start(f.backend.refreshAssertion)
	select {case <-f.attached:case <-time.After(3*time.Second):t.Fatal("idle native file owner did not attach refreshed proof")}
	unlocked,err:=f.backend.lockWorkloadSession(t.Context());if err!=nil{t.Fatal(err)};unlocked()
	current,err:=f.backend.workload.Session()
	if err!=nil || current.Id!=f.initial.Id || current.Credential!=f.initial.Credential || !current.IdentityExpiresAt.After(f.initial.IdentityExpiresAt) || f.preparations.Load()!=1 {t.Fatal("native source replaced its original prepared session",err)}
}

func TestEnvironmentNativeTokenEnvironmentIsPrivateAndNotBackgroundSource(t *testing.T) {
	f:=newIdentityRefreshFixture(t)
	request:=environmentRefreshRequest(f)
	f.backend.scope.Environment=&request.Selection
	f.backend.environmentSource=request.Source
	f.backend.directory=t.TempDir()
	request.Acquisition=&workload.Acquisition{Method:"token-env",TokenEnv:"EXPLICIT_TOKEN"}
	request.Environment=&connectorruntime.SDKEnvironment{TokenEnv:"EXPLICIT_TOKEN",TokenValue:"fresh.private.jwt"}
	if err:=f.backend.configureEnvironmentAcquisition(request);err!=nil{t.Fatal(err)}
	request.Environment.TokenValue="later.unrelated.jwt"
	proof,err:=f.backend.acquireEnvironmentAssertion(t.Context())
	if err!=nil || proof!="fresh.private.jwt" || f.backend.refreshAssertion!=nil {t.Fatal("token-env resampled a request or became a background minting source",err)}
	if f.attachments.Load()!=0 {t.Fatal("acquisition itself attached unrequested authority")}
}

func TestEnvironmentSharedChallengeConsumesExactReplyOnce(t *testing.T) {
	f:=newIdentityRefreshFixture(t)
	request:=environmentRefreshRequest(f)
	f.backend.scope.Environment=&request.Selection
	f.backend.environmentSource=request.Source
	f.backend.directory=t.TempDir()
	first,err:=f.backend.IdentityChallenge();if err!=nil{t.Fatal(err)}
	first.Selection.Services["db"]="http"
	second,err:=f.backend.IdentityChallenge();if err!=nil{t.Fatal(err)}
	if second.Selection.Services["db"]!="postgres" {t.Fatal("returned challenge aliased immutable selection")}
	if _,err:=f.backend.consumeEnvironmentReply(authorityv1.IdentitySourceReply{Schema:1,ChallengeId:first.Id,Assertion:"fresh.private.jwt"});err==nil {t.Fatal("replaced challenge reply accepted")}
	reply:=authorityv1.IdentitySourceReply{Schema:1,ChallengeId:second.Id,Assertion:"fresh.private.jwt"}
	if _,err:=f.backend.consumeEnvironmentReply(reply);err!=nil {t.Fatal(err)}
	if _,err:=f.backend.consumeEnvironmentReply(reply);err==nil {t.Fatal("consumed reply reused")}
	third,err:=f.backend.IdentityChallenge();if err!=nil{t.Fatal(err)}
	if third.NativePublicKey!=second.NativePublicKey || third.SessionId!=second.SessionId || third.BindingDigest!=second.BindingDigest {t.Fatal("fresh challenge rebound original native tuple")}
	f.backend.identityMu.Lock();f.backend.environmentChallenge.ExpiresAt=time.Now().Add(-time.Second);f.backend.identityMu.Unlock()
	if _,err:=f.backend.consumeEnvironmentReply(authorityv1.IdentitySourceReply{Schema:1,ChallengeId:third.Id,Assertion:"fresh.private.jwt"});err==nil {t.Fatal("expired delivery accepted")}
}

func TestEnvironmentExplicitWarmNativeSourcesNeverFallBackToVerifiedProof(t *testing.T) {
	f:=newIdentityRefreshFixture(t)
	request:=environmentRefreshRequest(f)
	f.backend.scope.Environment=&request.Selection
	f.backend.environmentSource=request.Source
	f.backend.directory=t.TempDir()
	request.Acquisition=&workload.Acquisition{Method:"token-env",TokenEnv:"EXPLICIT_TOKEN"}
	request.Environment=&connectorruntime.SDKEnvironment{TokenEnv:"EXPLICIT_TOKEN",TokenValue:"initial.private.jwt"}
	if err:=f.backend.configureEnvironmentAcquisition(request);err!=nil{t.Fatal(err)}
	for range 10 {
		if err:=f.backend.UseEnvironmentIdentity(t.Context(),connectorruntime.Request{SDKEnvironment:request.Environment});err!=nil{t.Fatal(err)}
	}
	if f.attachments.Load()!=0 || f.preparations.Load()!=1 {t.Fatal("matching warm native proof created authority work")}
	if err:=f.backend.UseEnvironmentIdentity(t.Context(),connectorruntime.Request{SDKEnvironment:&connectorruntime.SDKEnvironment{}});err==nil {t.Fatal("missing source input fell back to accepted proof")}
	if f.attachments.Load()!=0 {t.Fatal("missing proof caused attachment")}
	if err:=f.backend.UseEnvironmentIdentity(t.Context(),connectorruntime.Request{SDKEnvironment:request.Environment});err!=nil{t.Fatal("explicit healthy source retry failed",err)}
	if err:=f.backend.UseEnvironmentIdentity(t.Context(),connectorruntime.Request{SDKEnvironment:&connectorruntime.SDKEnvironment{TokenEnv:"EXPLICIT_TOKEN",TokenValue:"fresh.private.jwt"}});err!=nil{t.Fatal("fresh native proof failed same-session attachment",err)}
	current,err:=f.backend.workload.Session()
	if err!=nil || current.Id!=f.initial.Id || current.Credential!=f.initial.Credential || f.preparations.Load()!=1 || f.attachments.Load()!=1 {t.Fatal("source rotation replaced or duplicated the original admission",err)}
}

func TestEnvironmentGitHubRefreshRequiresOneExactPrivateJobSource(t *testing.T) {
	f:=newIdentityRefreshFixture(t)
	base:=environmentRefreshRequest(f)
	base.Acquisition=&workload.Acquisition{Method:"github-actions",Audience:"https://identity.example/job"}
	base.GitHubActionsRefresh=&connectorruntime.GitHubActionsRefresh{Audience:base.Acquisition.Audience,RequestURL:"https://runtime.example/token",RequestToken:"private.job.bearer"}
	for _,invalid:=range []string{"", "audience", "url", "token", "dual", "method", "source"} {t.Run(invalid,func(t *testing.T){
		request:=base;request.Acquisition=new(*base.Acquisition);request.GitHubActionsRefresh=new(*base.GitHubActionsRefresh)
		switch invalid {case "audience":request.GitHubActionsRefresh.Audience="other";case "url":request.GitHubActionsRefresh.RequestURL="http://runtime.example/token";case "token":request.GitHubActionsRefresh.RequestToken="";case "dual":request.Environment=&connectorruntime.SDKEnvironment{};case "method":request.Acquisition=&workload.Acquisition{Method:"fly-machine-api",Audience:base.Acquisition.Audience};case "source":request.Source=authorityv1.IdentitySourceSelection{Kind:"registered_key",MachineId:base.Source.MachineId,KeyId:"key"}}
		b:=&connectorConnectionBackend{}
		err:=b.configureEnvironmentAcquisition(request)
		if (err==nil)!=(invalid=="") {t.Fatal("private GitHub source validation",invalid,err)}
		if err==nil && (b.refreshAssertion==nil || b.environmentAcquire==nil) {t.Fatal("explicit job source did not retain acquisition/refresh")}
		if err!=nil && (b.refreshAssertion!=nil || b.environmentAcquire!=nil || b.environmentAcquisition!=nil) {t.Fatal("rejected job source enabled acquisition before its boundary check")}
	})}
	if strings.Contains(base.GitHubActionsRefresh.String(),"private.job") {t.Fatal("job source exposed bearer in diagnostics")}
}

func TestEnvironmentDefinitivePrepareDenialNeverReplaysAsCleanup(t *testing.T) {
	for _, lost:=range []bool{false,true} {t.Run(map[bool]string{false:"definitive",true:"earlier uncertain delivery"}[lost],func(t *testing.T){
		var calls atomic.Int32
		server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
			attempt:=calls.Add(1)
			if lost && attempt==1 {connection,_,err:=w.(http.Hijacker).Hijack();if err!=nil{t.Error(err);return};_ = connection.Close();return}
			w.Header().Set("Content-Type","application/json");w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"code":"forbidden","message":"the selected saved provider denied proof"})
		}));defer server.Close()
		client,err:=workload.New(server.URL,server.Client());if err!=nil{t.Fatal(err)}
		selection:=connectorruntime.EnvironmentSelection{Environment:controlv1.EnvironmentReference{Server:server.URL,ProjectKey:"project",EnvironmentId:"env_0123456789ABCDEFGHIJKL"},PermissionID:"mwp_0123456789ABCDEFGHIJKL",Services:map[string]string{"db":"postgres"}}
		b:=&connectorConnectionBackend{scope:connectorruntime.Context{Environment:&selection},connectorConnectionSession:connectorConnectionSession{workload:client},assertion:"original.signed.proof"}
		if _,err:=b.startEnvironment(t.Context());err==nil{t.Fatal("saved provider denial accepted")}
		err=b.Close(t.Context())
		if !lost && (err!=nil || calls.Load()!=1 || b.environmentPreparationUncertain) {t.Fatal("definitive denial replayed preparation during cleanup",calls.Load(),err)}
		if lost && (err==nil || calls.Load()!=3 || !b.environmentPreparationUncertain) {t.Fatal("earlier uncertain delivery was falsely reported clean",calls.Load(),err)}
	})}
}
