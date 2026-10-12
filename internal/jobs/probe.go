package jobs

import (
	"context"

	"github.com/riverqueue/river"

	"osee-testops-lite/internal/core"
)

type ProbeArgs struct {
	ID core.ID `json:"id"`
}

func (ProbeArgs) Kind() string { return "foundation_probe" }

type ProbeWorker struct {
	river.WorkerDefaults[ProbeArgs]
}

func (*ProbeWorker) Work(ctx context.Context, j *river.Job[ProbeArgs]) error {
	_, e := core.ParseID(string(j.Args.ID))
	if e != nil {
		return e
	}
	return ctx.Err()
}
