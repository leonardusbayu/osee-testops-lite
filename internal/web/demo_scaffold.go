package web

import (
	"net/http"
	"osee-testops-lite/internal/db"
)

func LocalDemoRouter(store *db.Store, origin string) (http.Handler, error) {
	return newPortalRouter(store, origin, true)
}
