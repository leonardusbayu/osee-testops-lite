package web

import (
	"context"
	"net/http"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/db"
)

type authSchemaPinger struct{ store *db.Store }

func (probe authSchemaPinger) Ping(ctx context.Context) error {
	if err := probe.store.Pool.Ping(ctx); err != nil {
		return err
	}
	var ready bool
	err := probe.store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_versions WHERE version=2) AND to_regclass('auth_principals') IS NOT NULL AND to_regclass('auth_invites') IS NOT NULL AND to_regclass('auth_sessions') IS NOT NULL`).Scan(&ready)
	if err != nil || !ready {
		return auth.ErrUnavailable
	}
	return nil
}

// LocalRouter serves the participant UI; demo access stays off unless explicitly opted in.
func LocalRouter(store *db.Store, origin string) (http.Handler, error) {
	return newPortalRouter(store, origin, false)
}
