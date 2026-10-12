package main

import (
	"context"
	"fmt"
	"os"
	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/demo"
	"time"
)

func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	if !c.DemoEnabled {
		return fmt.Errorf("explicit development demo opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := db.Open(ctx, c.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	return demo.Seed(ctx, store)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic demo seed refused or failed; no implicit repair attempted")
		os.Exit(1)
	}
	fmt.Println("explicit local participant demo seed verified")
}
