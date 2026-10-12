package sessions

import (
	"context"
	"errors"
	"testing"
)

func TestStaffSessionAssignmentRequiresEnrolledStaff(t *testing.T) {
	f := testFixture(t)
	unenrolled := id(t)
	exec(t, f.store, "insert into auth_principals(id,role,enabled) values($1,'admin',true)", unenrolled)
	f.authorized(t, func(ctx context.Context) {
		in := command(f)
		in.AssignedStaffID = unenrolled
		if _, err := f.service.Create(ctx, f.actor, in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("role-only assignee accepted: %v", err)
		}
		if count(t, f, "select count(*) from sessions") != 0 || count(t, f, "select count(*) from session_schedule_history") != 0 || count(t, f, "select count(*) from outbox") != 0 {
			t.Fatal("unenrolled assignment left effects")
		}
		created := create(t, f, ctx)
		update := change(created)
		update.AssignedStaffID = unenrolled
		if _, err := f.service.Reschedule(ctx, f.actor, created.ID, update); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("reschedule assigned an unenrolled principal")
		}
		if count(t, f, "select count(*) from session_schedule_history") != 1 {
			t.Fatal("unenrolled reschedule left history")
		}
	})
}
