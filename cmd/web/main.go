package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/web"
)

func run() error {
	c, e := config.Load()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opening, cancel := context.WithTimeout(ctx, 5*time.Second)
	s, e := db.Open(opening, c.DatabaseURL)
	cancel()
	if e != nil {
		return e
	}
	defer s.Close()
	handler, e := web.LocalRouter(s, c.AuthOrigin)
	if c.DemoEnabled {
		handler, e = web.LocalDemoRouter(s, c.AuthOrigin)
	}
	if e != nil {
		return e
	}
	server := web.NewServer(c.ListenAddress, handler)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	fmt.Println("local participant web started; outbound disabled")
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e = server.Shutdown(shutdown); e != nil {
			_ = server.Close()
			return e
		}
		return nil
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "web startup or shutdown failed; check local configuration and database availability")
		os.Exit(1)
	}
}
