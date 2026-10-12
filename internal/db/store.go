package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"osee-testops-lite/db/migrations"
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*Store, error) {
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return nil, errors.New("invalid database configuration")
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, errors.New("database unavailable")
	}
	return &Store{Pool: p}, nil
}
func (s *Store) Close() { s.Pool.Close() }
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, "select pg_advisory_xact_lock(73629104)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_versions(version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		return e
	}
	for _, migration := range []struct {
		version int64
		sql     string
	}{{1, migrations.Core}, {2, migrations.Auth}, {3, migrations.DevelopmentFixture}, {4, migrations.Sessions}, {5, migrations.Intake}, {6, migrations.Integrations}, {7, migrations.DartSync}, {8, migrations.StaffIdentity}} {
		var done bool
		if e = tx.QueryRow(ctx, "select exists(select 1 from schema_versions where version=$1)", migration.version).Scan(&done); e != nil {
			return e
		}
		if !done {
			if _, e = tx.Exec(ctx, migration.sql); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "insert into schema_versions(version) values($1)", migration.version); e != nil {
				return e
			}
		}
	}
	migrator, e := rivermigrate.New(riverpgxv5.New(s.Pool), nil)
	if e != nil {
		return e
	}
	if _, e = migrator.MigrateTx(ctx, tx, rivermigrate.DirectionUp, nil); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func (s *Store) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(tx)
	if e = fn(tx); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
