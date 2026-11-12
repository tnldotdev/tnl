package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/sys/unix"
)

func explicitEnvironmentStart() connectorruntime.EnvironmentStart {
	return connectorruntime.EnvironmentStart{Schema:1,Source:authorityv1.IdentitySourceSelection{Kind:"oidc",MachineId:"mci_0123456789ABCDEFGHIJKL"},Selection:connectorruntime.EnvironmentSelection{Environment:controlv1.EnvironmentReference{Server:"https://control.example",ProjectKey:"project",EnvironmentId:"env_0123456789ABCDEFGHIJKL"},PermissionID:"mwp_0123456789ABCDEFGHIJKL",Services:map[string]string{"api":"http","db":"postgres"}}}
}

func TestEnvironmentStartupIgnoresRetiredArtifactsAndProjectConfig(t *testing.T) {
	for _,kind:=range []string{"invalid", "symlink", "fifo"} {t.Run(kind,func(t *testing.T){
		root:=t.TempDir();t.Chdir(root)
		generated:=filepath.Join(root,".tnl","generated");if err:=os.MkdirAll(generated,0o700);err!=nil{t.Fatal(err)}
		if err:=os.WriteFile(filepath.Join(root,"tnl.config.ts"),[]byte("throw new Error('must not evaluate runtime configuration')"),0o600);err!=nil{t.Fatal(err)}
		artifact:=filepath.Join(generated,"workloads.json")
		switch kind {
		case "invalid":if err:=os.WriteFile(artifact,[]byte(`{"assertion":"must-not-read","target":"http://private-target.invalid"}`),0o600);err!=nil{t.Fatal(err)}
		case "symlink":if err:=os.Symlink(filepath.Join(root,"missing-private-target"),artifact);err!=nil{t.Fatal(err)}
		case "fifo":if err:=unix.Mkfifo(artifact,0o600);err!=nil{t.Fatal(err)}
		}
		request:=explicitEnvironmentStart();encoded,err:=json.Marshal(request);if err!=nil{t.Fatal(err)}
		var output bytes.Buffer
		done:=make(chan error,1)
		go func(){done<-ServeEnvironment(t.Context(),OwnerServeOptions{OwnerStartOptions:OwnerStartOptions{ParentPID:os.Getpid()}},io.NopCloser(bytes.NewReader(append(encoded,'\n'))),&output)}()
		select {case err:=<-done:if err==nil {t.Fatal("startup without a source reply succeeded")};case <-time.After(2*time.Second):
			if kind=="fifo" {fd,err:=unix.Open(artifact,unix.O_WRONLY|unix.O_NONBLOCK,0);if err==nil {_=unix.Close(fd)}}
			<-done;t.Fatal("explicit environment startup read or blocked on a retired artifact")
		}
		var challenge authorityv1.IdentitySourceChallenge
		if err:=connectorruntime.ReadJSON(bytes.NewReader(output.Bytes()),&challenge);err!=nil{t.Fatal("explicit startup consulted the project/artifact before issuing its defining challenge",err)}
		if err:=machineproof.ValidateSourceChallenge(challenge,time.Now());err!=nil{t.Fatal(err)}
		if challenge.Source!=request.Source || challenge.Selection==nil || challenge.Selection.Environment!=request.Selection.Environment || challenge.Selection.PermissionId!=request.Selection.PermissionID || len(challenge.Selection.Services)!=2 {t.Fatal("startup changed explicit selection")}
		for _,secret:=range []string{root,"private-target","must-not-read","must not evaluate"} {if bytes.Contains(output.Bytes(),[]byte(secret)){t.Fatal("challenge acquired checkout, target or secret context")}}
	})}
}

func TestEnvironmentContextPinsExactEnvironmentAndRequestedSubset(t *testing.T) {
	request:=explicitEnvironmentStart()
	first:=environmentContext(request.Selection,t.TempDir())
	if err:=first.Validate();err!=nil{t.Fatal(err)}
	if first.TeamID!="" || first.SourceID!="" || !reflect.DeepEqual(first.Services,[]string{"api","db"}) {t.Fatal("environment context invented team/source identity or widened selected services")}
	secondSelection:=request.Selection
	secondSelection.Environment.EnvironmentId="env_abcdefghijklmnopqrstuv"
	second:=environmentContext(secondSelection,first.Directory)
	if second.ConfigDigest==first.ConfigDigest || second.Environment.Environment==first.Environment.Environment {t.Fatal("distinct environments crossed owner context")}
	for _,extra:=range []string{`"publisher_group_id":"pgrp_0123456789ABCDEFGHIJKL"`,`"workloads":{}`,`"assertion":"must-not-persist"`} {
		encoded,err:=json.Marshal(request);if err!=nil{t.Fatal(err)}
		encoded=append(encoded[:len(encoded)-1],[]byte(","+extra+"}")...)
		var decoded connectorruntime.EnvironmentStart
		if connectorruntime.ReadJSON(bytes.NewReader(encoded),&decoded)==nil {t.Fatal("retired alternate context/secret shape accepted",extra)}
	}
}

func TestEnvironmentAggregateRejectsPrivateSourceBeforeDetachedLaunch(t *testing.T) {
	for _, mismatch := range []string{"method", "audience"} {
		t.Run(mismatch, func(t *testing.T) {
			request := explicitEnvironmentStart()
			request.Acquisition = &workload.Acquisition{Method: "github-actions", Audience: request.Selection.Environment.Server}
			request.GitHubActionsRefresh = &connectorruntime.GitHubActionsRefresh{Audience: request.Acquisition.Audience, RequestURL: "https://runtime.example/token", RequestToken: "private.job.bearer"}
			if mismatch == "method" {
				request.Acquisition.Method = "fly-machine-api"
			} else {
				request.GitHubActionsRefresh.Audience = "https://other.example"
			}
			encoded, err := json.Marshal(request)
			if err != nil { t.Fatal(err) }
			root := t.TempDir()
			var output bytes.Buffer
			err = StartEnvironmentOwner(t.Context(), OwnerStartOptions{RunnerTemp: root}, bytes.NewReader(encoded), &output)
			if !errors.Is(err, connectorruntime.ErrInvalid) || output.Len() != 0 {
				t.Fatal("private source rejection lost its exact reason or published readiness", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid private source allocated a detached owner", err)
			}
		})
	}
}
