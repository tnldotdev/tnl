package invocation

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// PublicOptions contains selected publication inputs, independent of CLI flags.
type PublicOptions struct {
	Target           string
	PreferredRegions []string
	TargetCAFile     string
	TargetTLSName    string
	ProjectRoot      string
	Project          clientproject.Project
	Service          string
	StateDir         string
	ServerURL        string
	AccessToken      string
	PublicURL        string
	Name             string
	Domain           string
	Team             string
	SelectedTeam     string
	Ephemeral        bool
	Demo             bool
	Anonymous        bool
	IP               []string
	Access           *config.Access
	Limits           publisher.ApplicationLimits
	InspectionMode   config.InspectionMode
	Inspection       *config.Inspection
	Resolver         target.TargetResolver
	Authenticate     func(context.Context, *clientstate.Database, string, string) (*auth.Client, error)
}

type ServiceOptions struct {
	PublicOptions
	Protocol                string
	ConfiguredPrivate       bool
	TargetTLS               *bool
	EnrollmentKey           string
	PublisherIdentityID     string
	PublisherCredentialFile string
	EnrollmentInput         io.Reader
	Install                 bool
	System                  bool
	ServiceName             string
	SystemStateDir          string
	ServerCAFile            string
	Installation            supervisor.ServiceOptions
}

type ServiceEvent struct {
	State     string
	ServiceID string
	Name      string
	Target    string
	Hostname  string
	Port      int
}

type ServicePresentation struct {
	Starting  func()
	Ready     func()
	Event     func(ServiceEvent) error
	Installed func([]supervisor.Job, string) error
}

type EnrolledOptions struct {
	PublicOptions
	Protocol            string
	TargetTLS           *bool
	Enrolled            bool
	WorkLimits          *config.Limits
	ReadinessPath       string
	SelectProtocol      func(controlv1.PublicURLServiceProtocol) (publisher.ApplicationLimits, error)
	SelectPrivate       func(controlv1.ServiceProtocol) (publisher.ApplicationLimits, error)
	ServicePresentation *ServicePresentation
}

type BackgroundOptions struct {
	ServiceOptions
	Open                  bool
	ServerFromConfig      bool
	InspectionModeFromCLI bool
	ReadinessPath         string
	SelectProtocol        func(string, bool) (publisher.ApplicationLimits, error)
}
