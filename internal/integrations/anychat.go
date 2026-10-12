package integrations

// Contract: https://documenter.getpostman.com/view/23223880/2sB2qi6x9D
// This adapter only reads metadata. The caller must obtain IDs from an approved
// mapping after identity verification; these vendor reads do not authenticate a
// participant. No email/phone search, message contents, ticket API, or writes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const anyChatEndpoint = "https://api.anychat.one/public/v1"
const anyChatMaxResponseBytes = 1 << 20

var (
	ErrAnyChatConfig       = errors.New("invalid AnyChat client configuration")
	ErrAnyChatInput        = errors.New("invalid AnyChat read parameters")
	ErrAnyChatResponse     = errors.New("invalid AnyChat response")
	ErrAnyChatScope        = errors.New("AnyChat reference outside configured scope")
	ErrAnyChatUnauthorized = errors.New("AnyChat authentication failed")
	ErrAnyChatUnavailable  = errors.New("AnyChat request unavailable")
)

type AnyChatConfig struct {
	APIKey        string
	WorkspaceGUID string
	ChannelGUID   string
	HTTPClient    *http.Client
}

func (AnyChatConfig) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "AnyChatConfig{credential:[REDACTED]}")
}

// AnyChatClient is bound to one workspace and one osee.co.id channel. Every
// read validates the current workspace metadata before returning chat data.
type AnyChatClient struct {
	apiKey, workspaceGUID, channelGUID string
	http                               *http.Client
}

func (client *AnyChatClient) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "AnyChatClient{credential:[REDACTED]}")
}

func NewAnyChatClient(config AnyChatConfig) (*AnyChatClient, error) {
	if !anyChatGUID(config.WorkspaceGUID) || !anyChatGUID(config.ChannelGUID) || !anyChatCredential(config.APIKey) {
		return nil, ErrAnyChatConfig
	}
	httpClient := http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		httpClient = *config.HTTPClient
		if httpClient.Timeout <= 0 || httpClient.Timeout > 30*time.Second {
			httpClient.Timeout = 15 * time.Second
		}
	}
	// Never forward x-api-key to redirects, even to another path on this host.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AnyChatClient{
		apiKey: config.APIKey, workspaceGUID: strings.ToLower(config.WorkspaceGUID),
		channelGUID: strings.ToLower(config.ChannelGUID), http: &httpClient,
	}, nil
}

func anyChatCredential(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return false
		}
	}
	return true
}

func anyChatGUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 || compact == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

// AnyChatHTTPError contains no upstream body, URL, credential, or contact data.
// RetryAfter is only a bounded hint; callers decide whether to retry.
type AnyChatHTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (err *AnyChatHTTPError) Error() string {
	return fmt.Sprintf("AnyChat HTTP status %d", err.StatusCode)
}

func (err *AnyChatHTTPError) Is(target error) bool {
	if err.StatusCode == http.StatusUnauthorized || err.StatusCode == http.StatusForbidden {
		return target == ErrAnyChatUnauthorized
	}
	return target == ErrAnyChatUnavailable
}

func (client *AnyChatClient) read(ctx context.Context, path string, destination any) error {
	if client == nil || client.http == nil {
		return ErrAnyChatConfig
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, anyChatEndpoint+path, nil)
	if err != nil {
		return ErrAnyChatInput
	}
	request.Header.Set("x-api-key", client.apiKey)
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrAnyChatUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		status := &AnyChatHTTPError{StatusCode: response.StatusCode}
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 86400 {
			status.RetryAfter = time.Duration(seconds) * time.Second
		}
		return status
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (contentType != "application/json" && !strings.HasSuffix(contentType, "+json")) {
		return ErrAnyChatResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, anyChatMaxResponseBytes+1))
	if err != nil || len(body) > anyChatMaxResponseBytes || json.Unmarshal(body, destination) != nil {
		return ErrAnyChatResponse
	}
	return nil
}

type AnyChatChannel struct {
	GUID      string `json:"guid"`
	Name      string `json:"name"`
	ClassName string `json:"class_name"`
	Status    int    `json:"status"`
}

type AnyChatWorkspace struct {
	GUID     string           `json:"guid"`
	Title    string           `json:"title"`
	Channels []AnyChatChannel `json:"channels"`
}

// Workspace verifies scope before returning metadata. Channel names alone do
// not establish ownership of a brand; ChannelGUID must come from staff review.
func (client *AnyChatClient) Workspace(ctx context.Context) (AnyChatWorkspace, error) {
	var workspace AnyChatWorkspace
	if err := client.read(ctx, "/workspace", &workspace); err != nil {
		return workspace, err
	}
	if !anyChatGUID(workspace.GUID) || !strings.EqualFold(workspace.GUID, client.workspaceGUID) {
		return AnyChatWorkspace{}, ErrAnyChatScope
	}
	// This is an OSEE response bound, not a claimed vendor plan quota.
	if workspace.Channels == nil || len(workspace.Channels) > 1000 {
		return AnyChatWorkspace{}, ErrAnyChatResponse
	}
	found := 0
	for _, channel := range workspace.Channels {
		if !anyChatGUID(channel.GUID) {
			return AnyChatWorkspace{}, ErrAnyChatResponse
		}
		if strings.EqualFold(channel.GUID, client.channelGUID) {
			found++
		}
	}
	if found != 1 {
		return AnyChatWorkspace{}, ErrAnyChatScope
	}
	return workspace, nil
}

// Only metadata needed for mapping/reconciliation is projected. Phone, email,
// notes, message text, attachment links, and payment/result data are omitted.
type AnyChatContact struct {
	GUID      string  `json:"guid"`
	Source    string  `json:"source"`
	SourceID  *string `json:"source_id"`
	CreatedAt int64   `json:"created_at"`
	UpdatedAt int64   `json:"updated_at"`
}

type AnyChatChat struct {
	GUID          string          `json:"guid"`
	Channel       string          `json:"channel"`
	AssignedTo    *string         `json:"assigned_to"`
	IsClosed      int             `json:"is_closed"`
	IsArchive     int             `json:"is_archive"`
	Mute          int             `json:"mute"`
	Source        string          `json:"source"`
	SourceID      *string         `json:"source_id"`
	Contact       *AnyChatContact `json:"contact"`
	CreatedAt     int64           `json:"created_at"`
	UpdatedAt     int64           `json:"updated_at"`
	LastMessageAt int64           `json:"last_message_at"`
}

func (client *AnyChatClient) Chat(ctx context.Context, chatGUID string) (AnyChatChat, error) {
	if !anyChatGUID(chatGUID) {
		return AnyChatChat{}, ErrAnyChatInput
	}
	if _, err := client.Workspace(ctx); err != nil {
		return AnyChatChat{}, err
	}
	var chat AnyChatChat
	if err := client.read(ctx, "/chat/"+strings.ToLower(chatGUID), &chat); err != nil {
		return AnyChatChat{}, err
	}
	if !anyChatGUID(chat.GUID) || !strings.EqualFold(chat.GUID, chatGUID) || !anyChatGUID(chat.Channel) || !strings.EqualFold(chat.Channel, client.channelGUID) {
		return AnyChatChat{}, ErrAnyChatScope
	}
	return chat, nil
}

// ContactForChat refuses to infer the contact from started_by, source_id, email,
// or phone. A null/unknown association requires staff reconciliation instead.
func (client *AnyChatClient) ContactForChat(ctx context.Context, chatGUID, contactGUID string) (AnyChatContact, error) {
	if !anyChatGUID(contactGUID) {
		return AnyChatContact{}, ErrAnyChatInput
	}
	chat, err := client.Chat(ctx, chatGUID)
	if err != nil {
		return AnyChatContact{}, err
	}
	if chat.Contact == nil || !anyChatGUID(chat.Contact.GUID) || !strings.EqualFold(chat.Contact.GUID, contactGUID) {
		return AnyChatContact{}, ErrAnyChatScope
	}
	var contact AnyChatContact
	if err := client.read(ctx, "/contact/"+strings.ToLower(contactGUID), &contact); err != nil {
		return AnyChatContact{}, err
	}
	if !anyChatGUID(contact.GUID) || !strings.EqualFold(contact.GUID, contactGUID) {
		return AnyChatContact{}, ErrAnyChatScope
	}
	return contact, nil
}
