package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/core"
)

type syncRow struct {
	id                                      core.ID
	version                                 int64
	hash                                    string
	task                                    DartTask
	external, state, mode, token            string
	active, reconcile, replayed, unresolved bool
	appliedVersion                          int64
	appliedHash                             string
	intentRecorded                          bool
}

func (r syncRow) receipt() DartSyncReceipt {
	return DartSyncReceipt{ExceptionID: r.id, SourceVersion: r.version, TaskID: r.external, State: r.state, Replayed: r.replayed}
}

type syncReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readSync(ctx context.Context, reader syncReader, id core.ID, lock bool) (syncRow, error) {
	if _, err := core.ParseID(string(id)); err != nil {
		return syncRow{}, ErrDartSyncInvalid
	}
	statement := `SELECT s.exception_id,s.source_version,s.desired_hash,s.desired_task,coalesce(s.external_task_id,''),s.state,coalesce(s.mutation_kind,''),coalesce(s.lease_token::text,''),coalesce(s.lease_until>clock_timestamp(),false),s.applied_version,coalesce(s.applied_hash,''),EXISTS(SELECT 1 FROM audit_events a WHERE a.object_id=s.exception_id AND a.action IN ('dart_exception_create_intent:'||s.source_version::text,'dart_exception_update_intent:'||s.source_version::text)) FROM dart_exception_sync s WHERE s.exception_id=$1`
	if lock {
		statement += " FOR UPDATE OF s"
	}
	var row syncRow
	var raw []byte
	err := reader.QueryRow(ctx, statement, id).Scan(&row.id, &row.version, &row.hash, &raw, &row.external, &row.state, &row.mode, &row.token, &row.active, &row.appliedVersion, &row.appliedHash, &row.intentRecorded)
	if err != nil {
		return row, err
	}
	if json.Unmarshal(raw, &row.task) != nil {
		return row, ErrDartSyncInvalid
	}
	return row, nil
}

func syncHistory(ctx context.Context, tx pgx.Tx, row syncRow) error {
	id, err := core.NewID()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO dart_exception_sync_history(id,exception_id,source_version,desired_hash,state,external_task_id) VALUES($1,$2,$3,$4,$5,nullif($6,''))`, id, row.id, row.version, row.hash, row.state, row.external); err != nil {
		return err
	}
	audit, err := core.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,object_id,action) VALUES($1,$2,$3)`, audit, row.id, "dart_exception_"+row.state+":"+strconv.FormatInt(row.version, 10))
	return err
}

func (s *DartSynchronizer) claim(ctx context.Context, id core.ID, version int64, hash string, task *DartTask, onlyReconcile bool) (syncRow, error) {
	var row syncRow
	var logical error
	err := s.store.WithTx(ctx, func(tx pgx.Tx) error {
		if task != nil {
			raw, err := json.Marshal(task)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO dart_exception_sync(exception_id,source_version,desired_hash,desired_task,state) VALUES($1,$2,$3,$4,'PENDING') ON CONFLICT(exception_id) DO NOTHING`, id, version, hash, raw); err != nil {
				return err
			}
		}
		var err error
		row, err = readSync(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if task != nil {
			if version < row.version {
				return ErrDartSyncStale
			}
			if version == row.version && hash != row.hash {
				return ErrDartSyncConflict
			}
		}
		if row.active {
			return ErrDartSyncBusy
		}
		uncertain := row.state == "UNCERTAIN" || (row.state == "SYNCING" && row.mode != "scan")
		row.unresolved = uncertain
		if task != nil && version > row.version && uncertain {
			row.state = "UNCERTAIN"
			if _, err = tx.Exec(ctx, `UPDATE dart_exception_sync SET state='UNCERTAIN',lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE exception_id=$1`, id); err != nil {
				return err
			}
			logical = ErrDartSyncUncertain
			return syncHistory(ctx, tx, row)
		}
		if !uncertain && row.state == "SYNCED" && (task == nil || version == row.version) {
			row.replayed = true
			return nil
		}
		if task != nil && version > row.version {
			row.version, row.hash, row.task = version, hash, *task
			raw, _ := json.Marshal(task)
			if _, err = tx.Exec(ctx, `UPDATE dart_exception_sync SET source_version=$2,desired_hash=$3,desired_task=$4,state='PENDING',mutation_kind=NULL,lease_token=NULL,lease_until=NULL WHERE exception_id=$1`, id, version, hash, raw); err != nil {
				return err
			}
		}
		row.reconcile = uncertain || onlyReconcile
		if !uncertain || row.mode == "" {
			row.mode = "scan"
		}
		if onlyReconcile && !uncertain && row.state == "PENDING" {
			row.reconcile = true
		}
		token, err := core.NewID()
		if err != nil {
			return err
		}
		row.token = string(token)
		row.state = "SYNCING"
		if _, err = tx.Exec(ctx, `UPDATE dart_exception_sync SET state='SYNCING',mutation_kind=$2,lease_token=$3,lease_until=clock_timestamp()+interval '2 minutes',updated_at=clock_timestamp() WHERE exception_id=$1`, id, row.mode, token); err != nil {
			return err
		}
		return syncHistory(ctx, tx, row)
	})
	if err != nil {
		if errors.Is(err, ErrDartSyncStale) || errors.Is(err, ErrDartSyncConflict) || errors.Is(err, ErrDartSyncBusy) {
			return row, err
		}
		return row, ErrDartUnavailable
	}
	return row, logical
}

func (s *DartSynchronizer) mutationIntent(ctx context.Context, row syncRow, kind string) error {
	err := s.store.WithTx(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE dart_exception_sync SET mutation_kind=$3,lease_until=clock_timestamp()+interval '2 minutes',updated_at=clock_timestamp() WHERE exception_id=$1 AND lease_token=$2::uuid AND state='SYNCING' AND lease_until>clock_timestamp()`, row.id, row.token, kind)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrDartSyncBusy
		}
		audit, err := core.NewID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,object_id,action) VALUES($1,$2,$3)`, audit, row.id, "dart_exception_"+kind+"_intent:"+strconv.FormatInt(row.version, 10))
		return err
	})
	if errors.Is(err, ErrDartSyncBusy) {
		return err
	}
	if err != nil {
		return ErrDartUnavailable
	}
	return nil
}

func (s *DartSynchronizer) finish(ctx context.Context, row syncRow, state, external string, outcome error) (DartSyncReceipt, error) {
	// Completion needs a fresh bounded context even when a provider timed out.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := s.store.WithTx(finishCtx, func(tx pgx.Tx) error {
		result, err := tx.Exec(finishCtx, `UPDATE dart_exception_sync SET state=$3,external_task_id=nullif($4,''),lease_token=NULL,lease_until=NULL,mutation_kind=CASE WHEN $3='UNCERTAIN' THEN CASE WHEN mutation_kind='scan' THEN CASE WHEN $4='' THEN 'create' ELSE 'update' END ELSE mutation_kind END ELSE NULL END,applied_version=CASE WHEN $3='SYNCED' THEN source_version ELSE applied_version END,applied_hash=CASE WHEN $3='SYNCED' THEN desired_hash ELSE applied_hash END,updated_at=clock_timestamp() WHERE exception_id=$1 AND lease_token=$2::uuid AND state='SYNCING' AND lease_until>clock_timestamp()`, row.id, row.token, state, external)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrDartSyncUncertain
		}
		row.state, row.external = state, external
		return syncHistory(finishCtx, tx, row)
	})
	if err != nil {
		row.state = "UNCERTAIN"
		return row.receipt(), ErrDartSyncUncertain
	}
	return row.receipt(), outcome
}
