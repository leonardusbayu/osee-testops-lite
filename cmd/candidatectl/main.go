package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

type bootstrapOptions struct {
	path  string
	reset bool
}

func executeBootstrap(ctx context.Context, identity *auth.StaffIdentity, options bootstrapOptions, output io.Writer) error {
	private, err := newCapabilityFile(options.path, options.reset)
	if err != nil {
		return auth.ErrForbidden
	}
	defer private.close()
	var challenge auth.StaffChallenge
	if options.reset {
		challenge, err = identity.ResetEmptyBootstrap(ctx)
	} else {
		challenge, err = identity.EnsureBootstrap(ctx)
	}
	if err != nil {
		return err
	}
	if err = private.publish(challenge.Token); err != nil {
		return auth.ErrUnavailable
	}
	return json.NewEncoder(output).Encode(struct {
		Status    string    `json:"status"`
		ExpiresAt time.Time `json:"expires_at"`
	}{"private_capability_written", challenge.ExpiresAt})
}

func bootstrapArguments(args []string) (bootstrapOptions, error) {
	var options bootstrapOptions
	if len(args) == 0 || args[0] != "bootstrap" {
		return options, auth.ErrForbidden
	}
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	empty := flags.Bool("empty-only", false, "")
	flags.BoolVar(&options.reset, "reset-empty", false, "")
	flags.StringVar(&options.path, "capability-file", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *empty == options.reset || options.path == "" {
		return bootstrapOptions{}, auth.ErrForbidden
	}
	return options, nil
}

func run(args []string, get func(string) string, output io.Writer) error {
	options, err := bootstrapArguments(args)
	if err != nil {
		return err
	}
	cfg, err := config.FromEnv(get)
	if err != nil || cfg.AuthOrigin != "http://127.0.0.1:8091" || cfg.DemoEnabled || (get("CANDIDATE_PROFILE") != "fixture" && get("CANDIDATE_PROFILE") != "local") {
		return auth.ErrForbidden
	}
	instance, err := core.ParseID(get("CANDIDATE_INSTANCE_ID"))
	if err != nil {
		return auth.ErrForbidden
	}
	key, err := readPrivateKey(get("STAFF_KEY_FILE"))
	if err != nil {
		return auth.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return auth.ErrUnavailable
	}
	defer store.Close()
	var actual string
	if err = store.Pool.QueryRow(ctx, "select current_database()").Scan(&actual); err != nil || actual != cfg.DatabaseIdentity {
		return auth.ErrForbidden
	}
	identity, err := auth.NewStaffIdentity(auth.NewService(store, nil), key, instance)
	if err != nil {
		return auth.ErrUnavailable
	}
	return executeBootstrap(ctx, identity, options, output)
}

func main() {
	if run(os.Args[1:], os.Getenv, os.Stdout) != nil {
		_, _ = io.WriteString(os.Stderr, "candidatectl refused or unavailable; no capability printed\n")
		os.Exit(1)
	}
}
