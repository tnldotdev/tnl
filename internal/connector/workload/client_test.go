package workload

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sessionFixture() authorityv1.EnvironmentVisitorSession {
	id := "wls_" + strings.Repeat("s", 22)
	now := time.Now()
	return authorityv1.EnvironmentVisitorSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, LeaseExpiresAt: now.Add(90 * time.Second), ExpiresAt: new(now.Add(time.Hour)), RenewAfter: now.Add(30 * time.Second), IdentityExpiresAt: now.Add(5 * time.Minute), ServiceIds: []string{"svc_" + strings.Repeat("p", 22)}}
}

func environmentFixture(server string) controlv1.EnvironmentReference {
	return controlv1.EnvironmentReference{Server: server, ProjectKey: "store", EnvironmentId: "env_" + strings.Repeat("e", 22)}
}

const permissionFixture = "mwp_pppppppppppppppppppppp"

func preparationFixture(server string, session authorityv1.EnvironmentVisitorSession) authorityv1.EnvironmentVisitorPreparation {
	return authorityv1.EnvironmentVisitorPreparation{Environment: environmentFixture(server), AppliedDefinitionRevision: 1, MutationRevision: 2, Session: session, Services: map[string]authorityv1.EnvironmentVisitorService{"db": {ServiceId: "svc_" + strings.Repeat("p", 22), Protocol: "postgres", Endpoint: controlv1.ServiceEndpoint{Hostname: "db.example", Port: 5432, Public: false}}}}
}

func prepareFixture(t *testing.T, client *Client) authorityv1.EnvironmentVisitorSession {
	t.Helper()
	result, err := client.Prepare(t.Context(), environmentFixture(client.server), permissionFixture, "assertion", map[string]string{"db": "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	return result.Session
}

func TestSessionUpdatesShareImmutableAndNarrowingBoundary(t *testing.T) {
	for _, operation := range []string{"renew", "attach"} {
		for _, tc := range []struct {
			name   string
			mutate func(*authorityv1.EnvironmentVisitorSession)
			accept bool
		}{
			{"unchanged", func(*authorityv1.EnvironmentVisitorSession) {}, true},
			{"fresh identity proof", func(s *authorityv1.EnvironmentVisitorSession) {
				s.IdentityExpiresAt = s.IdentityExpiresAt.Add(time.Minute)
			}, true},
			{"identity expiry rollback", func(s *authorityv1.EnvironmentVisitorSession) {
				s.IdentityExpiresAt = s.IdentityExpiresAt.Add(-time.Minute)
			}, false},
			{"lease beyond proof", func(s *authorityv1.EnvironmentVisitorSession) { s.IdentityExpiresAt = time.Now().Add(time.Second) }, false},
			{"expired identity", func(s *authorityv1.EnvironmentVisitorSession) { s.IdentityExpiresAt = time.Now().Add(-time.Second) }, false},
			{"unbounded identity", func(s *authorityv1.EnvironmentVisitorSession) { s.IdentityExpiresAt = time.Now().Add(13 * time.Hour) }, false},
			{"negative sequence", func(s *authorityv1.EnvironmentVisitorSession) { s.RenewalSequence = -1 }, false},
			{"sequence rollback", func(s *authorityv1.EnvironmentVisitorSession) { s.RenewalSequence = 1 }, false},
			{"sequence jump", func(s *authorityv1.EnvironmentVisitorSession) { s.RenewalSequence += 2 }, false},
			{"shorter expiry", func(s *authorityv1.EnvironmentVisitorSession) { s.ExpiresAt = new(s.ExpiresAt.Add(-time.Minute)) }, true},
			{"current authority can narrow", func(s *authorityv1.EnvironmentVisitorSession) { s.ServiceIds = []string{} }, true},
			{"id", func(s *authorityv1.EnvironmentVisitorSession) {
				s.Id = "wls_" + strings.Repeat("a", 22)
				s.Subject.WorkloadSessionId = new(s.Id)
			}, false},
			{"credential", func(s *authorityv1.EnvironmentVisitorSession) { s.Credential = "wlc_" + strings.Repeat("z", 43) }, false},
			{"longer expiry", func(s *authorityv1.EnvironmentVisitorSession) { s.ExpiresAt = new(s.ExpiresAt.Add(time.Minute)) }, false},
			{"removed hard expiry", func(s *authorityv1.EnvironmentVisitorSession) { s.ExpiresAt = nil }, false},
			{"subject", func(s *authorityv1.EnvironmentVisitorSession) {
				s.Subject.WorkloadSessionId = new("wls_" + strings.Repeat("a", 22))
			}, false},
			{"expanded rights", func(s *authorityv1.EnvironmentVisitorSession) {
				s.ServiceIds = append(s.ServiceIds, "svc_"+strings.Repeat("a", 22))
			}, false},
			{"replaced rights", func(s *authorityv1.EnvironmentVisitorSession) { s.ServiceIds[0] = "svc_" + strings.Repeat("a", 22) }, false},
			{"expired lease", func(s *authorityv1.EnvironmentVisitorSession) { s.LeaseExpiresAt = time.Now().Add(-time.Second) }, false},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				original := sessionFixture()
				original.RenewalSequence = 2
				next := cloneSession(original)
				if operation == "renew" {
					next.RenewalSequence++
				}
				tc.mutate(&next)
				var server *httptest.Server
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if strings.HasSuffix(r.URL.Path, "/prepare") {
						_ = json.NewEncoder(w).Encode(preparationFixture(server.URL, original))
					} else {
						_ = json.NewEncoder(w).Encode(next)
					}
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				prepareFixture(t, client)
				before, _ := client.Session()
				var updated authorityv1.EnvironmentVisitorSession
				if operation == "renew" {
					updated, err = client.Renew(t.Context())
				} else {
					updated, err = client.Attach(t.Context(), "new.assertion")
				}
				if (err == nil) != tc.accept {
					t.Fatalf("accepted = %t, want %t: %v", err == nil, tc.accept, err)
				}
				saved, _ := client.Session()
				if !tc.accept {
					if !reflect.DeepEqual(saved, before) || updated.Id != "" {
						t.Fatal("failed update changed confirmed authority")
					}
					return
				}
				if !reflect.DeepEqual(saved, updated) {
					t.Fatal("successful narrowing not retained")
				}
				if len(updated.ServiceIds) > 0 {
					updated.ServiceIds[0] = "changed"
				}
				*updated.Subject.WorkloadSessionId = "changed"
				*updated.ExpiresAt = time.Time{}
				after, _ := client.Session()
				if !reflect.DeepEqual(saved, after) {
					t.Fatal("returned update aliases retained authority")
				}
			})
		}
	}
}

func TestRenewalLostResponseRetryAndSerialization(t *testing.T) {
	original := sessionFixture()
	stored := cloneSession(original)
	var public ed25519.PublicKey
	var lost authorityv1.EnvironmentVisitorRenewal
	requests, applied := 0, 0
	var mu sync.Mutex
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/prepare") {
			var body authorityv1.EnvironmentVisitorPrepareRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			public, _ = base64.RawURLEncoding.DecodeString(body.PublicKey)
			_ = json.NewEncoder(w).Encode(preparationFixture(server.URL, original))
			return
		}
		var body authorityv1.EnvironmentVisitorRenewal
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		sig, _ := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
		if !ed25519.Verify(public, workloadproof.Renew(original.Id, body.Sequence), sig) || r.Header.Get("Authorization") != "Bearer "+original.Credential {
			t.Error("renewal lost its key or credential")
			w.WriteHeader(403)
			return
		}
		requests++
		if body.Sequence == stored.RenewalSequence+1 {
			stored.RenewalSequence = body.Sequence
			applied++
		} else if body.Sequence != stored.RenewalSequence {
			t.Error("renewal skipped a sequence")
			return
		}
		if requests == 1 {
			lost = body
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		if requests == 2 && !reflect.DeepEqual(body, lost) {
			t.Error("lost response retried another proof")
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	prepareFixture(t, client)
	before, _ := client.Session()
	if _, err := client.Renew(t.Context()); err == nil {
		t.Fatal("lost response reported success")
	}
	if saved, _ := client.Session(); !reflect.DeepEqual(saved, before) {
		t.Fatal("unacknowledged renewal changed authority")
	}
	if retried, err := client.Renew(t.Context()); err != nil || retried.RenewalSequence != 1 {
		t.Fatal("retry failed", err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if _, err := client.Renew(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	mu.Lock()
	defer mu.Unlock()
	if saved, _ := client.Session(); saved.RenewalSequence != 9 || applied != 9 || requests != 10 {
		t.Fatal("renewals not serialized or retry applied twice", saved.RenewalSequence, applied, requests)
	}
}

func TestSessionSequenceUpdatesAndOverflow(t *testing.T) {
	for _, operation := range []string{"renew", "attach", "prepare"} {
		for _, sequence := range []int64{-1, 1, 2, 3, 4, math.MaxInt64} {
			t.Run(operation+"/"+strconv.FormatInt(sequence, 10), func(t *testing.T) {
				original := sessionFixture()
				original.RenewalSequence = 2
				calls := 0
				var server *httptest.Server
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					value := cloneSession(original)
					if calls > 1 {
						value.RenewalSequence = sequence
					}
					w.Header().Set("Content-Type", "application/json")
					if strings.HasSuffix(r.URL.Path, "/prepare") {
						_ = json.NewEncoder(w).Encode(preparationFixture(server.URL, value))
					} else {
						_ = json.NewEncoder(w).Encode(value)
					}
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				prepareFixture(t, client)
				before, _ := client.Session()
				switch operation {
				case "renew":
					_, err = client.Renew(t.Context())
				case "attach":
					_, err = client.Attach(t.Context(), "assertion")
				case "prepare":
					_, err = client.Prepare(t.Context(), environmentFixture(server.URL), permissionFixture, "assertion", map[string]string{"db": "postgres"})
				}
				accepted := sequence == 3 || operation != "renew" && sequence == 2
				if (err == nil) != accepted {
					t.Fatal("unexpected sequence acceptance", err)
				}
				if !accepted {
					if saved, _ := client.Session(); !reflect.DeepEqual(saved, before) {
						t.Fatal("invalid sequence changed authority")
					}
				}
			})
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("overflow sent HTTP request") }))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.session = sessionFixture()
	client.session.RenewalSequence = math.MaxInt64
	if _, err := client.Renew(t.Context()); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestEnvironmentPreparationBindsExactSelectionAndPossession(t *testing.T) {
	for _, field := range []string{"valid", "server", "project", "environment", "service name", "service id", "protocol", "endpoint", "revision", "mutation", "duplicate id", "extra service"} {
		t.Run(field, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body authorityv1.EnvironmentVisitorPrepareRequest
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid request")
					return
				}
				public, _ := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
				sig, _ := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
				if !ed25519.Verify(public, machineproof.EnvironmentVisitorPossession("store", permissionFixture, environmentFixture(server.URL).EnvironmentId, "prepare", body.PublicKey, body.Nonce, map[string]string{"db": "postgres"}, sha256.Sum256([]byte(body.Assertion))), sig) {
					t.Error("selection was not bound to possession")
				}
				result := preparationFixture(server.URL, sessionFixture())
				service := result.Services["db"]
				switch field {
				case "server":
					result.Environment.Server = "https://other.example"
				case "project":
					result.Environment.ProjectKey = "other"
				case "environment":
					result.Environment.EnvironmentId = "env_" + strings.Repeat("x", 22)
				case "service name":
					delete(result.Services, "db")
					result.Services["other"] = service
				case "service id":
					service.ServiceId = "svc_" + strings.Repeat("x", 22)
					result.Services["db"] = service
				case "protocol":
					service.Protocol = "http"
					result.Services["db"] = service
				case "endpoint":
					service.Endpoint.Hostname = "127.0.0.1"
					result.Services["db"] = service
				case "revision":
					result.AppliedDefinitionRevision = 0
				case "mutation":
					result.MutationRevision = 0
				case "duplicate id":
					result.Session.ServiceIds = append(result.Session.ServiceIds, result.Session.ServiceIds[0])
				case "extra service":
					result.Services["extra"] = service
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Prepare(t.Context(), environmentFixture(server.URL), permissionFixture, "assertion", map[string]string{"db": "postgres"})
			if (err == nil) != (field == "valid") {
				t.Fatal("unexpected exact selection acceptance", field, err)
			}
			if err == nil {
				result.Services["db"] = authorityv1.EnvironmentVisitorService{}
				result.Session.ServiceIds[0] = "changed"
				saved, err := client.Preparation()
				if err != nil || saved.Services["db"].ServiceId == "" || saved.Session.ServiceIds[0] == "changed" {
					t.Fatal("preparation aliases caller state", err)
				}
			}
		})
	}
}

func TestSessionDecoderPreservesSDKWireAssertions(t *testing.T) {
	mutations := map[string]func(map[string]any){}
	for _, field := range []string{"provider", "github", "run_id", "run_attempt", "check_run_id", "unknown", "binding", "team_id", "project_key", "workload", "assertion_expires_at"} {
		mutations["retired/"+field] = func(w map[string]any) { w[field] = "retired" }
	}
	for _, field := range []string{"renewal_sequence", "identity_expires_at", "lease_expires_at", "service_ids", "subject", "credential", "id", "renew_after"} {
		mutations["missing/"+field] = func(w map[string]any) { delete(w, field) }
		mutations["null/"+field] = func(w map[string]any) { w[field] = nil }
	}
	for index, value := range []any{-1, "0", 0.5, json.Number("9223372036854775808")} {
		mutations["invalid sequence/"+strconv.Itoa(index)] = func(w map[string]any) { w["renewal_sequence"] = value }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(sessionFixture())
			var wire map[string]any
			_ = json.Unmarshal(data, &wire)
			mutate(wire)
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				result := preparationFixture(server.URL, sessionFixture())
				data, _ := json.Marshal(result)
				var outer map[string]any
				_ = json.Unmarshal(data, &outer)
				outer["session"] = wire
				_ = json.NewEncoder(w).Encode(outer)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Prepare(t.Context(), environmentFixture(server.URL), permissionFixture, "assertion", map[string]string{"db": "postgres"}); err == nil {
				t.Fatal("invalid native wire accepted")
			}
		})
	}
}

func TestRegisteredKeySourceUsesNativeChallengeForPrepareAndAttach(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const machine, keyID = "machine-source", "registered-key"
	session := sessionFixture()
	var client *Client
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		operation := "prepare"
		var assertion, signature string
		if strings.HasSuffix(request.URL.Path, "/prepare") {
			var body authorityv1.EnvironmentVisitorPrepareRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			assertion, signature = body.Assertion, body.Signature
		} else {
			operation = "attach"
			var body authorityv1.EnvironmentVisitorAssertion
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			assertion, signature = body.Assertion, body.Signature
		}
		grant, audience := client.ProofScope(environmentFixture(server.URL), permissionFixture, operation, map[string]string{"db": "postgres"})
		if _, err := publisherproof.Verify(assertion, machine, keyID, grant, audience, public, time.Now()); err != nil {
			t.Error("source key proof did not bind native challenge", err)
		}
		if public.Equal(client.PublicKey()) || signature == "" {
			t.Error("source and ephemeral possession keys were merged")
		}
		w.Header().Set("Content-Type", "application/json")
		if operation == "prepare" {
			_ = json.NewEncoder(w).Encode(preparationFixture(server.URL, session))
		} else {
			_ = json.NewEncoder(w).Encode(session)
		}
	}))
	defer server.Close()
	client, err = New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	proof := func(operation string) string {
		grant, audience := client.ProofScope(environmentFixture(server.URL), permissionFixture, operation, map[string]string{"db": "postgres"})
		token, err := publisherproof.Sign(machine, keyID, grant, audience, private, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	if _, err := client.Prepare(t.Context(), environmentFixture(server.URL), permissionFixture, proof("prepare"), map[string]string{"db": "postgres"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Attach(t.Context(), proof("attach")); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareReplayCannotRetargetIssuedIDsAfterRemovalOrRollback(t *testing.T) {
	for _, revision := range []int64{1, 3} {
		t.Run(strconv.FormatInt(revision, 10), func(t *testing.T) {
			calls := 0
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				result := preparationFixture(server.URL, sessionFixture())
				if calls > 1 {
					result.AppliedDefinitionRevision = revision
					result.MutationRevision++
					s := result.Services["db"]
					s.ServiceId = "svc_" + strings.Repeat("n", 22)
					result.Services["db"] = s
					result.Session.ServiceIds = []string{s.ServiceId}
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			prepareFixture(t, client)
			before, _ := client.Preparation()
			if _, err := client.Prepare(t.Context(), environmentFixture(server.URL), permissionFixture, "assertion", map[string]string{"db": "postgres"}); err == nil {
				t.Fatal("replay followed a replaced saved ID")
			}
			after, _ := client.Preparation()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected replay changed retained selection")
			}
		})
	}
}

func TestPrepareRetainsFullIntentAsCurrentAuthorityNarrows(t *testing.T) {
	for _, lost := range []bool{false, true} { t.Run(strconv.FormatBool(lost),func(t *testing.T){
		original := sessionFixture()
		apiID := "svc_" + strings.Repeat("a",22)
		original.ServiceIds = append(original.ServiceIds, apiID)
		protocols := map[string]string{"db":"postgres","api":"http"}
		calls:=0; mode:="narrow"; var firstPublic, firstNonce string; var server *httptest.Server
		server=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
			calls++
			var request authorityv1.EnvironmentVisitorPrepareRequest
			if err:=json.NewDecoder(r.Body).Decode(&request);err!=nil {t.Error(err);return}
			if len(request.Services)!=2 || request.Services["db"]!="postgres" || request.Services["api"]!="http" {t.Error("current view rewrote original request protocols")}
			if calls==1 {firstPublic,firstNonce=request.PublicKey,request.Nonce} else if request.PublicKey!=firstPublic || request.Nonce!=firstNonce {t.Error("retry replaced its native key or nonce")}
			public,_:=base64.RawURLEncoding.DecodeString(request.PublicKey);signature,_:=base64.RawURLEncoding.DecodeString(request.Signature)
			if !ed25519.Verify(public,machineproof.EnvironmentVisitorPossession("store",permissionFixture,environmentFixture(server.URL).EnvironmentId,"prepare",request.PublicKey,request.Nonce,protocols,sha256.Sum256([]byte(request.Assertion))),signature) {t.Error("retry did not sign complete original intent")}
			if calls==1 && lost {connection,_,err:=w.(http.Hijacker).Hijack();if err!=nil{t.Error(err);return};_ = connection.Close();return}
			result:=preparationFixture(server.URL,cloneSession(original))
			api:=authorityv1.EnvironmentVisitorService{ServiceId:apiID,Protocol:"http",Endpoint:controlv1.ServiceEndpoint{Hostname:"api.example",Port:443}}
			if calls==1 || mode=="expand" {result.Services["api"]=api} else {result.Session.ServiceIds=result.Session.ServiceIds[:1]}
			if calls>1 {result.AppliedDefinitionRevision=1;result.MutationRevision=3}
			if mode=="replace" {db:=result.Services["db"];db.ServiceId="svc_"+strings.Repeat("n",22);result.Services["db"]=db;result.Session.ServiceIds=[]string{db.ServiceId}}
			w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(result)
		}));defer server.Close()
		client,err:=New(server.URL,server.Client());if err!=nil {t.Fatal(err)}
		first,err:=client.Prepare(t.Context(),environmentFixture(server.URL),permissionFixture,"first.assertion",protocols)
		if lost && err==nil || !lost && err!=nil {t.Fatal("unexpected initial delivery",err)}
		if lost {if _,err:=client.Session();err==nil {t.Fatal("lost reply fabricated a confirmed session")}} else if len(first.Services)!=2 {t.Fatal("initial selection incomplete")}
		narrowed,err:=client.Prepare(t.Context(),environmentFixture(server.URL),permissionFixture,"fresh.assertion",protocols)
		if err!=nil || len(narrowed.Services)!=1 || len(narrowed.Session.ServiceIds)!=1 || narrowed.Session.Id!=original.Id || narrowed.Session.Credential!=original.Credential || !narrowed.Session.ExpiresAt.Equal(*original.ExpiresAt) {t.Fatal("same-intent retry did not retain narrowed original admission",err)}
		if len(client.expected)!=2 || client.expected["api"]!="http" {t.Fatal("narrowed response rewrote complete intent")}
		pin:=client.Binding(); before,_:=client.Preparation()
		for _, rejected := range []string{"expand","replace"} {mode=rejected;if _,err:=client.Prepare(t.Context(),environmentFixture(server.URL),permissionFixture,"another.assertion",protocols);err==nil {t.Fatal("narrowed admission was restored or replaced",rejected)};after,_:=client.Preparation();if !reflect.DeepEqual(before,after) || client.Binding()!=pin {t.Fatal("rejected response changed retained current view or immutable binding")}}
	})}
}
