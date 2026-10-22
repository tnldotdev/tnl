package invocation

import (
	"context"
	"io"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// PublicOptions contains selected publication inputs, independent of CLI flags.
type PublicOptions struct {
	Target         string
	TargetCAFile   string
	TargetTLSName  string
	ProjectRoot    string
	Project        projectconfig.Project
	Service        string
	StateDir       string
	ServerURL      string
	AccessToken    string
	PublicURL      string
	Name           string
	Domain         string
	Team           string
	SelectedTeam   string
	Ephemeral      bool
	Demo           bool
	Anonymous      bool
	IP             []string
	Access         *config.Access
	Limits         publisher.ApplicationLimits
	InspectionMode config.InspectionMode
	Inspection     *config.Inspection
	Resolver       target.TargetResolver
	Authenticate   func(context.Context, *clientstate.Database, string, string) (*clientauth.Client, error)
}

type PrivateOptions struct {
	PublicOptions
	Protocol          string
	ConfiguredPrivate bool
	TargetTLS         *bool
	EnrollmentKey     string
	PublisherID       string
	PublisherFile     string
	EnrollmentInput   io.Reader
	Install           bool
	System            bool
	ServiceName       string
	SystemStateDir    string
	ServerCAFile      string
	Installation      publisherjob.ServiceOptions
}

type PrivateEvent struct {
	State            string
	PrivateServiceID string
	Name             string
	Target           string
	Hostname         string
	Port             int
}

type PrivatePresentation struct {
	Starting  func()
	Ready     func()
	Event     func(PrivateEvent) error
	Installed func([]publisherjob.Job, string) error
}

type EnrolledOptions struct {
	PublicOptions
	Protocol            string
	TargetTLS           *bool
	Enrolled            bool
	WorkLimits          *config.Limits
	ReadinessPath       string
	SelectProtocol      func(controlv1.PublicURLServiceProtocol) (publisher.ApplicationLimits, error)
	SelectPrivate       func(controlv1.PrivateServiceProtocol) (publisher.ApplicationLimits, error)
	PrivatePresentation *PrivatePresentation
}

type BackgroundOptions struct {
	PrivateOptions
	Open                  bool
	ServerFromConfig      bool
	InspectionModeFromCLI bool
	ReadinessPath         string
	SelectProtocol        func(string, bool) (publisher.ApplicationLimits, error)
}
