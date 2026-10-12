package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/db"
)

func run() error {
	c, e := config.Load()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, e := db.Open(ctx, c.DatabaseURL)
	if e != nil {
		return e
	}
	defer s.Close()
	return s.Migrate(ctx)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "migration failed; check local configuration and database availability")
		os.Exit(1)
	}
	fmt.Println("local foundation migrations applied")
}
