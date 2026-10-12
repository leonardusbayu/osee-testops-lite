package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validGatewayConfig() gatewayConfig {
	return gatewayConfig{ListenAddress: "127.0.0.1:8120", DatabaseURL: "postgresql://fixture:synthetic@127.0.0.1:55438/osee_testops_test?sslmode=disable", Sources: map[string]string{"tinycommand": strings.Repeat("s", 32)}}
}

func TestGatewayConfigRestrictsLocalDestinationsAndSecrets(t *testing.T) {
	if validateGatewayConfig(validGatewayConfig()) != nil {
		t.Fatal("valid local config rejected")
	}
	for _, address := range []string{"0.0.0.0:8120", ":8120", "localhost:8120", "192.168.1.10:8120", "127.0.0.1:0", "127.0.0.1:65536"} {
		config := validGatewayConfig()
		config.ListenAddress = address
		if !errors.Is(validateGatewayConfig(config), errGatewayConfig) {
			t.Errorf("listener accepted: %s", address)
		}
	}
	for _, database := range []string{"postgresql://fixture:synthetic@remote.example:5432/osee_testops_test", "postgresql://fixture:synthetic@127.0.0.1:5432/unrelated_business", "postgresql://fixture@127.0.0.1:5432/osee_testops_test", "postgresql://fixture:synthetic@127.0.0.1/osee_testops_test", "postgresql://fixture:synthetic@127.0.0.1:5432/osee_testops_test?options=-csearch_path%3Dother", "postgresql://fixture:synthetic@127.0.0.1:5432/osee_testops_", "postgresql://fixture:synthetic@127.0.0.1:5432/osee_testops_test?sslmode=disable;options=ignored", "postgresql://fixture:synthetic@127.0.0.1:5432/osee_testops_test?sslmode=disable&sslmode=require", "postgresql://fixture:synthetic@127.0.0.1:5432/osee_testops_test?sslmode=%zz"} {
		config := validGatewayConfig()
		config.DatabaseURL = database
		if !errors.Is(validateGatewayConfig(config), errGatewayConfig) {
			t.Fatal("database destination accepted")
		}
	}
	for _, sources := range []map[string]string{nil, {}, {"tinycommand": "short"}, {"unknown": strings.Repeat("s", 32)}, {"tinycommand": strings.Repeat("s", 257)}} {
		config := validGatewayConfig()
		config.Sources = sources
		if !errors.Is(validateGatewayConfig(config), errGatewayConfig) {
			t.Fatal("invalid source secrets accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", validGatewayConfig(), validGatewayConfig()), "synthetic") {
		t.Fatal("configuration exposed database secret")
	}
}

func TestGatewayStrictFileRejectsAmbiguousConfiguration(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "valid.json")
	if err := os.WriteFile(valid, []byte(`{"listen_address":"127.0.0.1:8120","database_url":"postgresql://fixture:synthetic@127.0.0.1:55438/osee_testops_test","sources":{"tinycommand":"ssssssssssssssssssssssssssssssss"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var decoded gatewayConfig
	if readStrictFile(valid, &decoded) != nil || validateGatewayConfig(decoded) != nil {
		t.Fatal("protected local configuration rejected")
	}
	for _, body := range []string{`{"listen_address":"127.0.0.1:8120","unknown":true}`, `{"listen_address":"127.0.0.1:8120","listen_address":"0.0.0.0:8120"}`, `{"sources":{"tinycommand":"one","tinycommand":"two"}}`, `{} {}`, `not-json`, strings.Repeat("x", 65537)} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		var config gatewayConfig
		if !errors.Is(readStrictFile(path, &config), errGatewayConfig) {
			t.Fatal("ambiguous configuration accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "missing.json")
	if !errors.Is(readStrictFile(path, new(gatewayConfig)), errGatewayConfig) {
		t.Fatal("missing file accepted")
	}
}

func TestGatewayOnlyMountsReceiptAndHealthRoutes(t *testing.T) {
	var calls int
	events := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	handler := gatewayHandler(events, func(context.Context) error { return nil })
	for _, test := range []struct {
		path, method string
		status       int
	}{
		{"/healthz", "GET", 200}, {"/healthz", "POST", 405}, {"/v1/integration-events", "POST", 202}, {"/v1/integration-events", "GET", 405}, {"/api/bookings", "POST", 404}, {"/v1/integration-events/extra", "POST", 404},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.RemoteAddr = "127.0.0.1:23456"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.status {
			t.Errorf("%s %s status=%d", test.method, test.path, recorder.Code)
		}
		if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("receiver emitted CORS permission")
		}
	}
	if calls != 2 {
		t.Fatal("unrelated routes reached receipt handler")
	}
}

func TestGatewayRejectsNonLoopbackRequestsAndRedactsHealthFailure(t *testing.T) {
	handler := gatewayHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("nonlocal event reached handler") }), func(context.Context) error { return errors.New("synthetic-secret database unavailable") })
	request := httptest.NewRequest("POST", "/v1/integration-events", nil)
	request.RemoteAddr = "192.168.0.2:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatal("nonlocal request accepted")
	}
	request = httptest.NewRequest("GET", "/healthz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 503 || strings.Contains(recorder.Body.String(), "synthetic-secret") {
		t.Fatal("health failure leaked raw error")
	}
}

func TestGatewayBoundedServerAndGracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := newGatewayServer(listener.Addr().String(), gatewayHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }), func(context.Context) error { return nil }))
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.WriteTimeout != 15*time.Second || server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 16*1024 {
		t.Fatal("unbounded HTTP server")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveGateway(ctx, server, listener) }()
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		cancel()
		t.Fatal("health endpoint unavailable")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("graceful shutdown did not finish")
	}
}

func TestGatewayInvalidCommandNeverStartsServer(t *testing.T) {
	for _, args := range [][]string{{"-unknown=private-value"}, {"-config", filepath.Join(t.TempDir(), "missing.json")}, {"unexpected"}} {
		if !errors.Is(runGateway(args, io.Discard), errGatewayConfig) {
			t.Fatal("invalid command accepted")
		}
	}
}
