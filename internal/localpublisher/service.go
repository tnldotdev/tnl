package localpublisher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// ServiceJob contains the private identity only while it travels over the
// installer process's stdin. service state seals it before the installer exits.
type ServiceJob struct {
	Server, PublicURLID, Target string
	Protocol                    controlv1.PublicURLServiceProtocol
	Identity                    publisherauth.InstalledIdentity
}

func ServiceStateRoot() string {
	if runtime.GOOS == "darwin" {
		return "/private/var/db/tnl/publisher"
	}
	return "/var/lib/tnl/publisher"
}

func openServiceState(ctx context.Context, root string) (*clientstate.Database, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("publisher service requires administrator privileges")
	}
	if root == "" {
		root = ServiceStateRoot()
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create publisher service state: %w", err)
	}
	return clientstate.OpenService(ctx, root)
}

func InstallServiceJob(ctx context.Context, input io.Reader) error {
	state, err := openServiceState(ctx, "")
	if err != nil {
		return err
	}
	defer state.Close()
	var job ServiceJob
	decoder := json.NewDecoder(io.LimitReader(input, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil {
		return errors.New("invalid publisher service job")
	}
	server, err := clientstate.CanonicalServer(job.Server)
	if err != nil || server != job.Server || job.Protocol == "" || job.Target == "" {
		return errors.New("invalid publisher service target or server")
	}
	auth, err := clientauth.PublisherClients(ctx, server, nil)
	if err != nil {
		return err
	}
	owner, err := publisherauth.Restore(auth.PublisherControl, auth.PublisherAuthority, job.Identity)
	if err != nil {
		return err
	}
	route, err := owner.CurrentURL(ctx)
	if err != nil {
		return err
	}
	if route.Id != job.PublicURLID || route.ServiceProtocol != job.Protocol || route.Target != "" && route.Target != job.Target ||
		route.Ephemeral || route.Purpose != controlv1.App {
		return errors.New("publisher job does not match its saved public URL")
	}
	identity, err := json.Marshal(job.Identity)
	if err != nil {
		return errors.New("invalid publisher identity")
	}
	if err := state.SavePublisherJob(ctx, clientstate.PublisherJob{
		PublicURLID: job.PublicURLID, Server: job.Server, Target: job.Target,
		Protocol: string(job.Protocol), Identity: identity,
	}); err != nil {
		return err
	}
	return activateService(ctx)
}

func ServeInstalledJobs(ctx context.Context, root string) error {
	state, err := openServiceState(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	return servePublisherJobs(ctx, state, 2*time.Second, runInstalledJob)
}

func servePublisherJobs(ctx context.Context, state *clientstate.Database, poll time.Duration,
	run func(context.Context, *clientstate.Database, clientstate.PublisherJob) error) error {
	var workers sync.WaitGroup
	active := map[string]context.CancelFunc{}
	defer func() {
		for _, cancel := range active {
			cancel()
		}
		workers.Wait()
	}()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		jobs, err := state.PublisherJobs(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		present := make(map[string]bool, len(jobs))
		for _, job := range jobs {
			present[job.PublicURLID] = true
			if _, exists := active[job.PublicURLID]; exists {
				continue
			}
			jobCtx, cancel := context.WithCancel(ctx)
			active[job.PublicURLID] = cancel
			workers.Add(1)
			go func() {
				defer workers.Done()
				for jobCtx.Err() == nil {
					if err := run(jobCtx, state, job); err != nil && jobCtx.Err() == nil {
						log.Printf("publisher service URL %s stopped: %v", job.PublicURLID, err)
					}
					select {
					case <-jobCtx.Done():
						return
					case <-time.After(3 * time.Second):
					}
				}
			}()
		}
		for id, cancel := range active {
			if !present[id] {
				cancel()
				delete(active, id)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func RemoveServiceJob(ctx context.Context, id string) error {
	if !opaqueid.Valid(id, opaqueid.PublicURLPrefix) {
		return errors.New("invalid background public URL ID")
	}
	state, err := openServiceState(ctx, "")
	if err != nil {
		return err
	}
	if err := state.DeletePublisherJob(ctx, id); err != nil {
		state.Close()
		return err
	}
	return state.Close()
}

func runInstalledJob(ctx context.Context, state *clientstate.Database, job clientstate.PublisherJob) error {
	var identity publisherauth.InstalledIdentity
	if err := json.Unmarshal(job.Identity, &identity); err != nil {
		return errors.New("invalid saved publisher identity")
	}
	auth, err := clientauth.PublisherClients(ctx, job.Server, nil)
	if err != nil {
		return err
	}
	owner, err := publisherauth.Restore(auth.PublisherControl, auth.PublisherAuthority, identity)
	if err != nil {
		return err
	}
	route, err := owner.CurrentURL(ctx)
	if err != nil {
		return err
	}
	if route.Id != job.PublicURLID || route.ServiceProtocol != controlv1.PublicURLServiceProtocol(job.Protocol) ||
		route.Target != "" && route.Target != job.Target || route.Ephemeral || route.Purpose != controlv1.App {
		return errors.New("saved publisher job does not match its public URL")
	}
	services, err := EnrolledServices(ctx, state, auth, route)
	if err != nil {
		return err
	}
	if route.ServiceProtocol == controlv1.Http {
		if err := localproxy.PreflightWithOptions(ctx, job.Target, localproxy.TargetOptions{}); err != nil {
			return err
		}
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = *route.AllowedIpPrefixes
	}
	configuration := services.Config(job.Target, allowed, publisher.ApplicationLimits{})
	configuration.Control = &publisherauth.RunControl{Client: auth.PublisherControl, Owner: owner}
	configuration.ServiceProtocol = route.ServiceProtocol
	configuration.PreserveSavedURLTarget = true
	configuration.ControlURL = auth.ServerEndpoint
	return publisher.Run(ctx, configuration)
}
