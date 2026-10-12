package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/jobs"
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
	client, e := jobs.NewClient(s.Pool)
	if e != nil {
		return e
	}
	if e = client.Start(ctx); e != nil {
		return e
	}
	fmt.Println("local inert probe worker started; outbound disabled")
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.Stop(shutdown)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "worker startup or shutdown failed; check migrations and local database availability")
		os.Exit(1)
	}
}
