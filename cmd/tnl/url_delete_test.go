package main

import (
	"context"
	"errors"
	"io"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestURLDeleteFlagDefaultsToProtectedDeletion(t *testing.T) {
	for _, unconditional := range []bool{false, true} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		args := []string{"url", "delete", "svc_0123456789abcdefghijkl"}
		if unconditional {
			args = append(args, "--unconditional")
		}
		if _, err := parser(args); err != nil || flags.URL.Delete.Unconditional != unconditional {
			t.Fatal("URL deletion lost its explicit unconditional choice", err)
		}
	}
}

type serviceDeletionFixture struct {
	current            controlv1.Service
	readErr, deleteErr error
	reads, deletes     int
	conditions         controlv1.DeleteServiceParams
}

func (f *serviceDeletionFixture) GetService(_ context.Context, id string) (controlv1.Service, error) {
	f.reads++
	if id != "svc_selected" {
		panic("changed management read selection")
	}
	return f.current, f.readErr
}

func (f *serviceDeletionFixture) DeleteService(_ context.Context, id string, conditions controlv1.DeleteServiceParams) error {
	f.deletes++
	if id != "svc_selected" {
		panic("changed deletion selection")
	}
	f.conditions = conditions
	return f.deleteErr
}

func TestURLDeleteUsesCurrentRevisionWithoutRetryingConflicts(t *testing.T) {
	for _, deletionErr := range []error{nil, clientcontrol.ErrStatusConflict} {
		f := &serviceDeletionFixture{current: controlv1.Service{Id: "svc_selected", ServiceRevision: 73}, deleteErr: deletionErr}
		err := deleteManagedService(t.Context(), f, "svc_selected", false)
		if !errors.Is(err, deletionErr) || f.reads != 1 || f.deletes != 1 ||
			f.conditions.ExpectedServiceRevision == nil || *f.conditions.ExpectedServiceRevision != 73 || f.conditions.UnconditionalDelete != nil {
			t.Fatal("ordinary deletion lost observed revision or retried a conflict", err, f)
		}
	}
}

func TestURLDeleteUnconditionalIsExplicitAndStillUsesManagement(t *testing.T) {
	f := &serviceDeletionFixture{deleteErr: clientcontrol.ErrNotFound}
	if err := deleteManagedService(t.Context(), f, "svc_selected", true); !errors.Is(err, clientcontrol.ErrNotFound) ||
		f.reads != 0 || f.deletes != 1 || f.conditions.ExpectedServiceRevision != nil ||
		f.conditions.UnconditionalDelete == nil || !*f.conditions.UnconditionalDelete {
		t.Fatal("explicit unconditional deletion lost management denial or condition", err, f)
	}
}

func TestURLDeleteDoesNotSubstituteIDOrTrustForServiceRevision(t *testing.T) {
	for _, current := range []controlv1.Service{
		{Id: "svc_selected", TrustRevision: 7}, {Id: "svc_other", ServiceRevision: 7},
	} {
		f := &serviceDeletionFixture{current: current}
		if err := deleteManagedService(t.Context(), f, "svc_selected", false); err == nil || f.deletes != 0 {
			t.Fatal("invalid management observation reached delete", err)
		}
	}
	f := &serviceDeletionFixture{readErr: clientcontrol.ErrNotFound}
	if err := deleteManagedService(t.Context(), f, "svc_selected", false); !errors.Is(err, clientcontrol.ErrNotFound) || f.deletes != 0 {
		t.Fatal("management read denial reached deletion", err)
	}
}
