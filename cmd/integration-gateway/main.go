// integration-gateway provides the local authenticated receipt boundary only.
// It never runs migrations or changes booking, payment, result or shipping state.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

var errGatewayConfig = errors.New("invalid integration gateway configuration")

type gatewayConfig struct {
	ListenAddress string            `json:"listen_address"`
	DatabaseURL   string            `json:"database_url"`
	Sources       map[string]string `json:"sources"`
}

func (gatewayConfig) String() string          { return "gatewayConfig{secrets:redacted}" }
func (config gatewayConfig) GoString() string { return config.String() }

func readStrictFile(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 65536 {
		return errGatewayConfig
	}
	// Windows mode bits do not represent NTFS ACLs; the local operator must limit
	// that file's ACL to the integration owner. Unix files must be owner-only.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errGatewayConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return errGatewayConfig
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(body) > 65536 || rejectDuplicateKeys(body) != nil {
		return errGatewayConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return errGatewayConfig
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errGatewayConfig
	}
	return nil
}

func rejectDuplicateKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errGatewayConfig
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return errGatewayConfig
				}
				seen[name] = true
				if walk() != nil {
					return errGatewayConfig
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errGatewayConfig
			}
		case '[':
			for decoder.More() {
				if walk() != nil {
					return errGatewayConfig
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errGatewayConfig
			}
		default:
			return errGatewayConfig
		}
		return nil
	}
	if walk() != nil {
		return errGatewayConfig
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errGatewayConfig
	}
	return nil
}

func validateGatewayConfig(config gatewayConfig) error {
	host, port, err := net.SplitHostPort(config.ListenAddress)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || (host != "127.0.0.1" && host != "::1") || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return errGatewayConfig
	}
	database, err := url.Parse(config.DatabaseURL)
	if err != nil || (database.Scheme != "postgresql" && database.Scheme != "postgres") || (database.Hostname() != "127.0.0.1" && database.Hostname() != "::1") || database.User == nil || database.User.Username() == "" || database.Fragment != "" {
		return errGatewayConfig
	}
	password, supplied := database.User.Password()
	databaseName := strings.TrimPrefix(database.Path, "/")
	if !supplied || password == "" || !strings.HasPrefix(databaseName, "osee_testops_") || len(databaseName) <= len("osee_testops_") || len(databaseName) > 63 {
		return errGatewayConfig
	}
	for _, character := range databaseName {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return errGatewayConfig
		}
	}
	portNumber, portErr = strconv.Atoi(database.Port())
	if portErr != nil || portNumber < 1 || portNumber > 65535 {
		return errGatewayConfig
	}
	query, err := url.ParseQuery(database.RawQuery)
	if err != nil {
		return errGatewayConfig
	}
	for key, values := range query {
		if len(values) != 1 {
			return errGatewayConfig
		}
		switch key {
		case "sslmode":
			if values[0] != "disable" && values[0] != "require" && values[0] != "verify-full" {
				return errGatewayConfig
			}
		case "connect_timeout":
			seconds, err := strconv.Atoi(values[0])
			if err != nil || seconds < 1 || seconds > 10 {
				return errGatewayConfig
			}
		default:
			return errGatewayConfig
		}
	}
	if len(config.Sources) < 1 || len(config.Sources) > 4 {
		return errGatewayConfig
	}
	for source, secret := range config.Sources {
		if len(integrations.SupportedEventKinds(source)) == 0 || len(secret) < 32 || len(secret) > 256 {
			return errGatewayConfig
		}
	}
	return nil
}

func gatewayHandler(events http.Handler, ready func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/integration-events", events)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, `{"error":"method_not_allowed"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if ready == nil || ready(ctx) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"unavailable"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hostname-based URLs and LAN interfaces are never accepted as the local
		// listening boundary. No CORS headers are emitted by this receiver.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "local access required", http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newGatewayServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
}

func serveGateway(ctx context.Context, server *http.Server, listener net.Listener) error {
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("integration gateway unavailable")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return errors.New("integration gateway shutdown failed")
		}
		return nil
	}
}

// catalogPreflight deliberately reads Services only, never appointments or
// customers. Secret-file fields decode into a separate unprinted local struct.
func catalogPreflight(ctx context.Context, path string, output io.Writer) error {
	var credentials struct {
		BaseURL      string `json:"base_url"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if readStrictFile(path, &credentials) != nil {
		return errGatewayConfig
	}
	client, err := integrations.NewTrafftClient(integrations.TrafftConfig{BaseURL: credentials.BaseURL, ClientID: credentials.ClientID, ClientSecret: credentials.ClientSecret})
	credentials.ClientID, credentials.ClientSecret = "", ""
	if err != nil {
		return errGatewayConfig
	}
	var services []integrations.TrafftService
	for pageNumber := 1; pageNumber <= 10; pageNumber++ {
		page, err := client.Services(ctx, pageNumber, 10)
		if err != nil {
			return errors.New("Trafft catalog unavailable")
		}
		services = append(services, page.Data...)
		if pageNumber >= page.Pagination.Pages {
			return json.NewEncoder(output).Encode(struct {
				Provider string                       `json:"provider"`
				Scope    string                       `json:"scope"`
				Services []integrations.TrafftService `json:"services"`
			}{Provider: "trafft", Scope: "services metadata only", Services: services})
		}
	}
	return errors.New("Trafft catalog exceeds bounded preflight")
}

func runGateway(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("integration-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", ".local/integrations/gateway.json", "Local protected JSON configuration")
	catalog := flags.Bool("trafft-catalog", false, "Read-only Services catalog preflight")
	credentialPath := flags.String("trafft-credentials", ".local/integrations/trafft.json", "Existing local Trafft credentials")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errGatewayConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *catalog {
		bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		return catalogPreflight(bounded, *credentialPath, output)
	}
	var config gatewayConfig
	if readStrictFile(*configPath, &config) != nil || validateGatewayConfig(config) != nil {
		return errGatewayConfig
	}
	opening, cancel := context.WithTimeout(ctx, 5*time.Second)
	store, err := db.Open(opening, config.DatabaseURL)
	cancel()
	if err != nil {
		return errors.New("integration database unavailable")
	}
	defer store.Close()
	secrets := make(map[string][]byte, len(config.Sources))
	for source, secret := range config.Sources {
		secrets[source] = []byte(secret)
	}
	events, err := integrations.NewEventGateway(store, integrations.EventConfig{Secrets: secrets})
	if err != nil {
		return errGatewayConfig
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return errors.New("integration listener unavailable")
	}
	defer listener.Close()
	_, _ = fmt.Fprintf(output, "integration gateway listening on %s; authenticated receipts only\n", config.ListenAddress)
	return serveGateway(ctx, newGatewayServer(config.ListenAddress, gatewayHandler(events, store.Pool.Ping)), listener)
}

func main() {
	if runGateway(os.Args[1:], os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "integration gateway failed; check protected local configuration, catalog access or database availability")
		os.Exit(1)
	}
}
