package integrations

// Trafft's account-linked API reference is the contract for this adapter:
// https://documenter.getpostman.com/view/1487056/2sAY4x9MRe
// Only token acquisition and reads are implemented. Availability and approval
// are observations, not payment evidence or permission to allocate exam seats.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const trafftMaxResponseBytes = 1024 * 1024

var (
	ErrTrafftConfig       = errors.New("invalid Trafft client configuration")
	ErrTrafftInput        = errors.New("invalid Trafft read parameters")
	ErrTrafftResponse     = errors.New("invalid Trafft response")
	ErrTrafftUnauthorized = errors.New("Trafft authentication failed")
	ErrTrafftUnavailable  = errors.New("Trafft request unavailable")
)

type TrafftConfig struct {
	BaseURL      string       `json:"base_url"`
	ClientID     string       `json:"-"`
	ClientSecret string       `json:"-"`
	HTTPClient   *http.Client `json:"-"`
}

func (TrafftConfig) String() string          { return "TrafftConfig{credentials:redacted}" }
func (config TrafftConfig) GoString() string { return config.String() }

// TrafftClient never exposes the access token or includes upstream response
// bodies in errors. Credentials and cached tokens remain in process memory.
type TrafftClient struct {
	base         *url.URL
	http         *http.Client
	clientID     string
	clientSecret string
	tokenMu      sync.Mutex
	token        string
	expiresAt    time.Time
}

func (*TrafftClient) String() string          { return "TrafftClient{credentials:redacted}" }
func (client *TrafftClient) GoString() string { return client.String() }

func NewTrafftClient(config TrafftConfig) (*TrafftClient, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || base.Port() != "" {
		return nil, ErrTrafftConfig
	}
	host := strings.ToLower(base.Hostname())
	tenant := strings.TrimSuffix(host, ".admin.trafft.com")
	if !strings.HasSuffix(host, ".admin.trafft.com") || tenant == "" || strings.Contains(tenant, ".") {
		return nil, ErrTrafftConfig
	}
	for _, char := range tenant {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
			return nil, ErrTrafftConfig
		}
	}
	if !trafftCredential(config.ClientID, 512) || !trafftCredential(config.ClientSecret, 4096) {
		return nil, ErrTrafftConfig
	}
	client := http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		client = *config.HTTPClient
		if client.Timeout <= 0 || client.Timeout > 30*time.Second {
			client.Timeout = 15 * time.Second
		}
	}
	// A redirect must never forward authentication to another destination.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	base.Host, base.Path = host, ""
	return &TrafftClient{base: base, http: &client, clientID: config.ClientID, clientSecret: config.ClientSecret}, nil
}

func trafftCredential(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return false
		}
	}
	return true
}

// TrafftHTTPError preserves only status and bounded retry delay, never response
// text. A nonzero RetryAfter is a hint; this client performs no automatic retry.
type TrafftHTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (err *TrafftHTTPError) Error() string {
	return fmt.Sprintf("Trafft HTTP status %d", err.StatusCode)
}

func (err *TrafftHTTPError) Is(target error) bool {
	if err.StatusCode == http.StatusUnauthorized || err.StatusCode == http.StatusForbidden {
		return target == ErrTrafftUnauthorized
	}
	return target == ErrTrafftUnavailable
}

func (client *TrafftClient) bearer(ctx context.Context) (string, error) {
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if client.token != "" && time.Now().Before(client.expiresAt) {
		return client.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {client.clientID}, "client_secret": {client.clientSecret}}
	var response struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	if err := client.request(ctx, http.MethodPost, "/api/v2/token", nil, form.Encode(), "", &response); err != nil {
		return "", err
	}
	if !strings.EqualFold(response.TokenType, "Bearer") || response.ExpiresIn < 1 || response.ExpiresIn > 86400 || !trafftCredential(response.AccessToken, 8192) {
		return "", ErrTrafftResponse
	}
	client.token = response.AccessToken
	client.expiresAt = time.Now().Add(time.Duration(response.ExpiresIn)*time.Second - 5*time.Second)
	return client.token, nil
}

func (client *TrafftClient) read(ctx context.Context, path string, query url.Values, destination any) error {
	if client == nil || client.http == nil {
		return ErrTrafftConfig
	}
	token, err := client.bearer(ctx)
	if err != nil {
		return err
	}
	err = client.request(ctx, http.MethodGet, path, query, "", token, destination)
	if errors.Is(err, ErrTrafftUnauthorized) {
		client.tokenMu.Lock()
		if client.token == token {
			client.token, client.expiresAt = "", time.Time{}
		}
		client.tokenMu.Unlock()
	}
	return err
}

func (client *TrafftClient) request(ctx context.Context, method, path string, query url.Values, form, token string, destination any) error {
	target := *client.base
	target.Path, target.RawQuery = path, query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(form))
	if err != nil {
		return ErrTrafftInput
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "OSEE-TestOps/0.1 (+https://osee.co.id)")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrTrafftUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		status := &TrafftHTTPError{StatusCode: response.StatusCode}
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 86400 {
			status.RetryAfter = time.Duration(seconds) * time.Second
		}
		return status
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, trafftMaxResponseBytes+1))
	if err != nil || len(body) > trafftMaxResponseBytes || json.Unmarshal(body, destination) != nil {
		return ErrTrafftResponse
	}
	return nil
}

type TrafftPagination struct {
	Total int `json:"total"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Pages int `json:"pages"`
}

type TrafftPage[T any] struct {
	Data       []T              `json:"data"`
	Pagination TrafftPagination `json:"pagination"`
}

type TrafftService struct {
	ID               int64       `json:"id"`
	Name             string      `json:"name"`
	Duration         int         `json:"duration"`
	BufferTimeBefore *int        `json:"buffer_time_before"`
	BufferTimeAfter  *int        `json:"buffer_time_after"`
	Price            json.Number `json:"price"`
}

// Unneeded phone/email fields are deliberately omitted from API projections.
type TrafftEmployee struct {
	ID        int64   `json:"id"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Timezone  *string `json:"timezone"`
}

type TrafftLocation struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

func trafftPageQuery(page, limit int) (url.Values, error) {
	// This is OSEE's bounded request policy, not a claimed vendor quota.
	if page < 1 || page > 100000 || limit < 1 || limit > 100 {
		return nil, ErrTrafftInput
	}
	return url.Values{"page": {strconv.Itoa(page)}, "limit": {strconv.Itoa(limit)}}, nil
}

type trafftRecord interface{ trafftID() int64 }

func (value TrafftService) trafftID() int64     { return value.ID }
func (value TrafftEmployee) trafftID() int64    { return value.ID }
func (value TrafftLocation) trafftID() int64    { return value.ID }
func (value TrafftAppointment) trafftID() int64 { return value.ID }

func trafftReadPage[T trafftRecord](ctx context.Context, client *TrafftClient, path string, query url.Values) (TrafftPage[T], error) {
	var page TrafftPage[T]
	if err := client.read(ctx, path, query, &page); err != nil {
		return TrafftPage[T]{}, err
	}
	expectedPage, _ := strconv.Atoi(query.Get("page"))
	expectedLimit, _ := strconv.Atoi(query.Get("limit"))
	if page.Data == nil || page.Pagination.Page != expectedPage || page.Pagination.Limit != expectedLimit || page.Pagination.Total < 0 || page.Pagination.Pages < 0 || len(page.Data) > expectedLimit {
		return TrafftPage[T]{}, ErrTrafftResponse
	}
	for _, row := range page.Data {
		if row.trafftID() < 1 {
			return TrafftPage[T]{}, ErrTrafftResponse
		}
	}
	return page, nil
}

func (client *TrafftClient) Services(ctx context.Context, page, limit int) (TrafftPage[TrafftService], error) {
	query, err := trafftPageQuery(page, limit)
	if err != nil {
		return TrafftPage[TrafftService]{}, err
	}
	return trafftReadPage[TrafftService](ctx, client, "/api/v2/services", query)
}

func (client *TrafftClient) Employees(ctx context.Context, page, limit int) (TrafftPage[TrafftEmployee], error) {
	query, err := trafftPageQuery(page, limit)
	if err != nil {
		return TrafftPage[TrafftEmployee]{}, err
	}
	return trafftReadPage[TrafftEmployee](ctx, client, "/api/v2/employees", query)
}

func (client *TrafftClient) Locations(ctx context.Context, page, limit int) (TrafftPage[TrafftLocation], error) {
	query, err := trafftPageQuery(page, limit)
	if err != nil {
		return TrafftPage[TrafftLocation]{}, err
	}
	return trafftReadPage[TrafftLocation](ctx, client, "/api/v2/locations", query)
}

func (client *TrafftClient) Service(ctx context.Context, id int64) (TrafftService, error) {
	var service TrafftService
	if id < 1 {
		return service, ErrTrafftInput
	}
	err := client.read(ctx, "/api/v2/services/"+strconv.FormatInt(id, 10), nil, &service)
	if err != nil {
		return TrafftService{}, err
	}
	if err == nil && service.ID != id {
		return TrafftService{}, ErrTrafftResponse
	}
	return service, err
}

type TrafftCustomerReference struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type TrafftBookingReference struct {
	ID                int64                   `json:"id"`
	Status            string                  `json:"status"`
	AdditionalPersons int                     `json:"additional_persons"`
	Customer          TrafftCustomerReference `json:"customer"`
}

type TrafftAppointment struct {
	ID            int64                    `json:"id"`
	Status        string                   `json:"status"`
	StartDateTime time.Time                `json:"start_date_time"`
	EndDateTime   time.Time                `json:"end_date_time"`
	Service       TrafftService            `json:"service"`
	Employees     []TrafftEmployee         `json:"employees"`
	Location      *TrafftLocation          `json:"location"`
	Bookings      []TrafftBookingReference `json:"bookings"`
	CreatedAt     time.Time                `json:"created_at"`
}

type TrafftAppointmentFilter struct {
	Page, Limit, CustomerID, EmployeeID, ServiceID, LocationID int
	Status, SortBy, SortOrder                                  string
}

func (client *TrafftClient) Appointments(ctx context.Context, filter TrafftAppointmentFilter) (TrafftPage[TrafftAppointment], error) {
	// This tenant also contains existing services for another OSEE brand. OSEE
	// reads require an explicit service scope although the vendor makes it optional.
	if filter.ServiceID < 1 {
		return TrafftPage[TrafftAppointment]{}, ErrTrafftInput
	}
	query, err := trafftPageQuery(filter.Page, filter.Limit)
	if err != nil {
		return TrafftPage[TrafftAppointment]{}, err
	}
	for key, value := range map[string]int{"customerId": filter.CustomerID, "employeeId": filter.EmployeeID, "serviceId": filter.ServiceID, "locationId": filter.LocationID} {
		if value < 0 {
			return TrafftPage[TrafftAppointment]{}, ErrTrafftInput
		}
		if value > 0 {
			query.Set(key, strconv.Itoa(value))
		}
	}
	if filter.Status != "" {
		switch filter.Status {
		case "approved", "pending", "canceled", "rejected", "no_show":
			query.Set("status", filter.Status)
		default:
			return TrafftPage[TrafftAppointment]{}, ErrTrafftInput
		}
	}
	if filter.SortBy != "" {
		if filter.SortBy != "start_time" && filter.SortBy != "created_at" {
			return TrafftPage[TrafftAppointment]{}, ErrTrafftInput
		}
		query.Set("sort_by", filter.SortBy)
	}
	if filter.SortOrder != "" {
		if filter.SortOrder != "asc" && filter.SortOrder != "desc" {
			return TrafftPage[TrafftAppointment]{}, ErrTrafftInput
		}
		query.Set("sort_order", filter.SortOrder)
	}
	return trafftReadPage[TrafftAppointment](ctx, client, "/api/v2/appointments", query)
}

type TrafftAvailableTimeFilter struct {
	StartDate, EndDate                                  string
	ServiceID, EmployeeID, LocationID, AdditionalGuests int
}

type TrafftAvailableDay struct {
	Date      string           `json:"date"`
	TimeSlots []TrafftTimeSlot `json:"timeSlots"`
}

type TrafftTimeSlot struct {
	Time      string  `json:"time"`
	Services  []int64 `json:"services"`
	Employees []int64 `json:"employees"`
	Locations []int64 `json:"locations"`
}

// AvailableTimes returns a provider observation. It does not reserve a seat and
// its clock strings must not be treated as WIB until account timezone is tested.
func (client *TrafftClient) AvailableTimes(ctx context.Context, filter TrafftAvailableTimeFilter) ([]TrafftAvailableDay, error) {
	start, startErr := time.Parse(time.DateOnly, filter.StartDate)
	end, endErr := time.Parse(time.DateOnly, filter.EndDate)
	if startErr != nil || endErr != nil || end.Before(start) || end.Sub(start) > 7*24*time.Hour || filter.ServiceID < 1 || filter.EmployeeID < 0 || filter.LocationID < 0 || filter.AdditionalGuests < 0 || filter.AdditionalGuests > 100 {
		return nil, ErrTrafftInput
	}
	query := url.Values{"calendar_start_date": {filter.StartDate}, "calendar_end_date": {filter.EndDate}, "service": {strconv.Itoa(filter.ServiceID)}, "additional_guest_count": {strconv.Itoa(filter.AdditionalGuests)}}
	if filter.EmployeeID > 0 {
		query.Set("employee", strconv.Itoa(filter.EmployeeID))
	}
	if filter.LocationID > 0 {
		query.Set("location", strconv.Itoa(filter.LocationID))
	}
	var days []TrafftAvailableDay
	if err := client.read(ctx, "/api/v2/available-times", query, &days); err != nil {
		return nil, err
	}
	if days == nil || len(days) > 8 {
		return nil, ErrTrafftResponse
	}
	for _, day := range days {
		date, err := time.Parse(time.DateOnly, day.Date)
		if err != nil || date.Before(start) || date.After(end) {
			return nil, ErrTrafftResponse
		}
		for _, slot := range day.TimeSlots {
			if _, err := time.Parse("15:04", slot.Time); err != nil {
				return nil, ErrTrafftResponse
			}
		}
	}
	return days, nil
}
