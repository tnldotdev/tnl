// package workloadfixture constructs nonsecret workload responses for client
// transport fixtures. real authorization suites must use trusted apply instead.
package workloadfixture

import (
	"fmt"
	"strings"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Application(name, team string, services []string) controlv1.RegisteredApplication {
	app := controlv1.RegisteredApplication{ClientId: "pub_" + strings.Repeat("A", 22), KeyId: "pkey_" + strings.Repeat("K", 22), TeamId: team, Name: name, Ownership: controlv1.RegisteredApplicationMember, Grants: []controlv1.PublisherGrant{}}
	for index, service := range services {
		app.Grants = append(app.Grants, controlv1.PublisherGrant{Id: fmt.Sprintf("pgrant_%022d", index+1), Kind: controlv1.PublisherGrantKindService, Operation: controlv1.ApplicationVisit, ServiceId: new(service), CreatedAt: time.Unix(1, 0).UTC()})
	}
	return app
}
