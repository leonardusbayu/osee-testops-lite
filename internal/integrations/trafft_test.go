package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type trafftTransport func(*http.Request) (*http.Response, error)

func (transport trafftTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func trafftResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func trafftTestClient(t *testing.T, handler trafftTransport) *TrafftClient {
	t.Helper()
	client, err := NewTrafftClient(TrafftConfig{BaseURL: "https://fixture.admin.trafft.com", ClientID: "synthetic-client", ClientSecret: "synthetic-secret", HTTPClient: &http.Client{Transport: handler}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestTrafftRejectsUntrustedDestinationAndCredentialControls(t *testing.T) {
	for _, base := range []string{"http://fixture.admin.trafft.com", "https://admin.trafft.com", "https://fixture.admin.trafft.com.evil.example", "https://nested.fixture.admin.trafft.com", "https://user:secret@fixture.admin.trafft.com", "https://fixture.admin.trafft.com:443", "https://fixture.admin.trafft.com/path", "https://fixture.admin.trafft.com?secret=value", "https://fixture.admin.trafft.com#fragment"} {
		t.Run(base, func(t *testing.T) {
			_, err := NewTrafftClient(TrafftConfig{BaseURL: base, ClientID: "fixture", ClientSecret: "fixture"})
			if !errors.Is(err, ErrTrafftConfig) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	for _, secret := range []string{"", "leading space", "secret\r\nHeader:value", strings.Repeat("x", 4097)} {
		_, err := NewTrafftClient(TrafftConfig{BaseURL: "https://fixture.admin.trafft.com", ClientID: "fixture", ClientSecret: secret})
		if !errors.Is(err, ErrTrafftConfig) {
			t.Fatal("invalid credential accepted")
		}
	}
}

func TestTrafftDocumentedTokenContractAndConcurrentCache(t *testing.T) {
	var tokens atomic.Int32
	var reads atomic.Int32
	client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "fixture.admin.trafft.com" || request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != "OSEE-TestOps/0.1 (+https://osee.co.id)" {
			t.Error("untrusted target or missing accept")
		}
		if request.URL.Path == "/api/v2/token" {
			tokens.Add(1)
			if request.Method != "POST" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("Authorization") != "" {
				t.Error("token request contract")
			}
			if err := request.ParseForm(); err != nil || request.PostForm.Get("grant_type") != "client_credentials" || request.PostForm.Get("client_id") != "synthetic-client" || request.PostForm.Get("client_secret") != "synthetic-secret" {
				t.Error("token form contract")
			}
			return trafftResponse(200, `{"token_type":"Bearer","expires_in":3600,"access_token":"synthetic-bearer"}`), nil
		}
		reads.Add(1)
		if request.Method != "GET" || request.URL.Path != "/api/v2/services" || request.URL.Query().Get("page") != "1" || request.URL.Query().Get("limit") != "10" || request.Header.Get("Authorization") != "Bearer synthetic-bearer" {
			t.Error("services request contract")
		}
		return trafftResponse(200, `{"data":[{"id":2,"name":"Synthetic service","duration":3600,"buffer_time_before":null,"buffer_time_after":1200,"price":120}],"pagination":{"total":1,"page":1,"limit":10,"pages":1}}`), nil
	})
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			page, err := client.Services(context.Background(), 1, 10)
			if err != nil || len(page.Data) != 1 || page.Data[0].ID != 2 || page.Data[0].Price.String() != "120" {
				t.Error("unexpected service projection")
			}
		})
	}
	group.Wait()
	if tokens.Load() != 1 || reads.Load() != 12 {
		t.Fatalf("calls token=%d reads=%d", tokens.Load(), reads.Load())
	}
}

func TestTrafftReadFiltersAndMinimizedProjection(t *testing.T) {
	client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/token" {
			return trafftResponse(200, `{"token_type":"Bearer","expires_in":3600,"access_token":"fixture-token"}`), nil
		}
		query := request.URL.Query()
		if request.URL.Path != "/api/v2/appointments" || query.Get("customerId") != "93" || query.Get("employeeId") != "1" || query.Get("serviceId") != "16" || query.Get("locationId") != "14" || query.Get("status") != "pending" || query.Get("sort_by") != "start_time" || query.Get("sort_order") != "desc" {
			t.Error("appointment filter mapping")
		}
		return trafftResponse(200, `{"data":[{"id":159,"status":"pending","start_date_time":"2026-04-02T20:00:00+07:00","end_date_time":"2026-04-02T21:00:00+07:00","service":{"id":16,"name":"Fixture"},"employees":[{"id":1,"first_name":"Synthetic","last_name":"Staff","email":"do-not-copy@example.com"}],"location":null,"bookings":[{"id":159,"status":"pending","additional_persons":0,"customer":{"id":93,"first_name":"Synthetic","last_name":"Candidate","email":"do-not-copy@example.com"}}],"created_at":"2026-04-01T10:00:00+00:00"}],"pagination":{"total":1,"page":1,"limit":1,"pages":1}}`), nil
	})
	page, err := client.Appointments(context.Background(), TrafftAppointmentFilter{Page: 1, Limit: 1, CustomerID: 93, EmployeeID: 1, ServiceID: 16, LocationID: 14, Status: "pending", SortBy: "start_time", SortOrder: "desc"})
	if err != nil || len(page.Data) != 1 || page.Data[0].Bookings[0].Customer.ID != 93 || page.Data[0].Status != "pending" || page.Data[0].StartDateTime.Hour() != 20 {
		t.Fatalf("projection failed: %v", err)
	}
	projection, err := json.Marshal(page)
	if err != nil || strings.Contains(string(projection), "do-not-copy") || strings.Contains(string(projection), "email") {
		t.Fatal("unneeded contact fields escaped projection")
	}
	// Pending remains pending; this adapter has no payment or confirmation mutation.
}

func TestTrafftConfigurationFormattingCannotDiscloseCredentials(t *testing.T) {
	config := TrafftConfig{BaseURL: "https://fixture.admin.trafft.com", ClientID: "private-client", ClientSecret: "private-secret"}
	client, err := NewTrafftClient(config)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{string(body), fmt.Sprintf("%+v %#v", config, config), fmt.Sprintf("%+v %#v", client, client)} {
		if strings.Contains(value, "private-client") || strings.Contains(value, "private-secret") {
			t.Fatal("credential appeared in configuration serialization")
		}
	}
}

func TestTrafftInvalidInputsDoNotMakeRequests(t *testing.T) {
	client := trafftTestClient(t, func(*http.Request) (*http.Response, error) {
		t.Error("invalid request reached transport")
		return nil, ErrTrafftUnavailable
	})
	ctx := context.Background()
	for _, pair := range [][2]int{{0, 10}, {1, 0}, {1, 101}, {100001, 10}} {
		if _, err := client.Services(ctx, pair[0], pair[1]); !errors.Is(err, ErrTrafftInput) {
			t.Error("invalid pagination accepted")
		}
	}
	if _, err := client.Service(ctx, 0); !errors.Is(err, ErrTrafftInput) {
		t.Error("invalid service ID accepted")
	}
	for _, filter := range []TrafftAppointmentFilter{{Page: 1, Limit: 1, CustomerID: -1}, {Page: 1, Limit: 1, Status: "paid"}, {Page: 1, Limit: 1, SortBy: "arbitrary"}, {Page: 1, Limit: 1, SortOrder: "arbitrary"}} {
		if _, err := client.Appointments(ctx, filter); !errors.Is(err, ErrTrafftInput) {
			t.Error("invalid filter accepted")
		}
	}
	for _, filter := range []TrafftAvailableTimeFilter{{StartDate: "2026-10-09", EndDate: "2026-10-17", ServiceID: 1}, {StartDate: "2026-10-10", EndDate: "2026-10-09", ServiceID: 1}, {StartDate: "bad", EndDate: "2026-10-09", ServiceID: 1}, {StartDate: "2026-10-09", EndDate: "2026-10-09", ServiceID: 0}} {
		if _, err := client.AvailableTimes(ctx, filter); !errors.Is(err, ErrTrafftInput) {
			t.Error("invalid date window accepted")
		}
	}
}

func TestTrafftAvailabilityIsBoundedProviderObservation(t *testing.T) {
	client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/token" {
			return trafftResponse(200, `{"token_type":"Bearer","expires_in":3600,"access_token":"fixture-token"}`), nil
		}
		q := request.URL.Query()
		if request.Method != "GET" || request.URL.Path != "/api/v2/available-times" || q.Get("calendar_start_date") != "2026-10-09" || q.Get("calendar_end_date") != "2026-10-16" || q.Get("service") != "16" || q.Get("employee") != "1" || q.Get("location") != "14" || q.Get("additional_guest_count") != "0" {
			t.Error("available times query contract")
		}
		return trafftResponse(200, `[{"date":"2026-10-09","timeSlots":[{"time":"09:00","services":[16],"employees":[1],"locations":[14]}]}]`), nil
	})
	days, err := client.AvailableTimes(context.Background(), TrafftAvailableTimeFilter{StartDate: "2026-10-09", EndDate: "2026-10-16", ServiceID: 16, EmployeeID: 1, LocationID: 14})
	if err != nil || len(days) != 1 || days[0].TimeSlots[0].Time != "09:00" {
		t.Fatalf("availability decode: %v", err)
	}
}

func TestTrafftResponseFailuresAreBoundedAndRedacted(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"missing-pagination", `{"data":[]}`, 200, ErrTrafftResponse},
		{"missing-ids", `{"data":[{"name":"fixture"}],"pagination":{"total":1,"page":1,"limit":1,"pages":1}}`, 200, ErrTrafftResponse},
		{"wrong-pagination", `{"data":[],"pagination":{"total":0,"page":2,"limit":1,"pages":0}}`, 200, ErrTrafftResponse},
		{"oversize", strings.Repeat("x", trafftMaxResponseBytes+1), 200, ErrTrafftResponse},
		{"bad-json", `{"secret":"sensitive-upstream-secret"} trailing`, 200, ErrTrafftResponse},
		{"unauthorized", `sensitive-upstream-secret`, 401, ErrTrafftUnauthorized},
		{"rate-limit", `sensitive-upstream-secret`, 429, ErrTrafftUnavailable},
		{"server-error", `sensitive-upstream-secret`, 500, ErrTrafftUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/api/v2/token" {
					return trafftResponse(200, `{"token_type":"Bearer","expires_in":3600,"access_token":"fixture-token"}`), nil
				}
				response := trafftResponse(test.status, test.body)
				response.Header.Set("Retry-After", "60")
				return response, nil
			})
			page, err := client.Services(context.Background(), 1, 1)
			if !errors.Is(err, test.want) || len(page.Data) != 0 || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("error should fail closed and redact: %v", err)
			}
			if test.status == 429 {
				var status *TrafftHTTPError
				if !errors.As(err, &status) || status.RetryAfter != time.Minute {
					t.Error("retry hint lost")
				}
			}
		})
	}
}

func TestTrafftUnauthorizedReadInvalidatesCachedTokenWithoutRetry(t *testing.T) {
	tokens, reads := 0, 0
	client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/token" {
			tokens++
			return trafftResponse(200, `{"token_type":"Bearer","expires_in":3600,"access_token":"fixture-token"}`), nil
		}
		reads++
		return trafftResponse(401, `do-not-log`), nil
	})
	for range 2 {
		if _, err := client.Services(context.Background(), 1, 1); !errors.Is(err, ErrTrafftUnauthorized) {
			t.Error("expected unauthorized")
		}
	}
	if tokens != 2 || reads != 2 {
		t.Fatal("unbounded retry or stale token cache")
	}
}

func TestTrafftNeverFollowsCredentialRedirect(t *testing.T) {
	var downstream atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { downstream.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	}))
	defer source.Close()
	// Replace the transport destination in a test only, leaving the public config
	// bound to an HTTPS Trafft tenant. Production does not allow this URL override.
	transport := source.Client().Transport
	client := trafftTestClient(t, func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		target := *request.URL
		target.Host = strings.TrimPrefix(source.URL, "https://")
		clone.URL = &target
		return transport.RoundTrip(clone)
	})
	_, err := client.Services(context.Background(), 1, 1)
	var status *TrafftHTTPError
	if !errors.As(err, &status) || status.StatusCode != 307 || downstream.Load() != 0 {
		t.Fatalf("credential redirect followed or misclassified: %v", err)
	}
}

func TestTrafftTokenResponseRejectsHeaderInjectionAndMalformedGrant(t *testing.T) {
	for _, body := range []string{`{"token_type":"Basic","expires_in":3600,"access_token":"fixture"}`, `{"token_type":"Bearer","expires_in":0,"access_token":"fixture"}`, `{"token_type":"Bearer","expires_in":3600,"access_token":"fixture\r\nHeader:value"}`} {
		client := trafftTestClient(t, func(*http.Request) (*http.Response, error) { return trafftResponse(200, body), nil })
		if _, err := client.Services(context.Background(), 1, 1); !errors.Is(err, ErrTrafftResponse) {
			t.Error("invalid token response accepted")
		}
	}
}
