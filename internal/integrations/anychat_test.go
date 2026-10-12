package integrations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	anyChatTestWorkspace = "11111111-1111-1111-1111-111111111111"
	anyChatTestChannel   = "22222222-2222-2222-2222-222222222222"
	anyChatTestChat      = "33333333-3333-3333-3333-333333333333"
	anyChatTestContact   = "44444444-4444-4444-4444-444444444444"
	anyChatTestOther     = "55555555-5555-5555-5555-555555555555"
	anyChatTestKey       = "synthetic-test-only-key"
)

type anyChatTestTransport func(*http.Request) (*http.Response, error)

func (transport anyChatTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func anyChatTestResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func anyChatTestConfig(transport anyChatTestTransport) AnyChatConfig {
	return AnyChatConfig{
		APIKey: anyChatTestKey, WorkspaceGUID: anyChatTestWorkspace, ChannelGUID: anyChatTestChannel,
		HTTPClient: &http.Client{Transport: transport},
	}
}

func anyChatWorkspaceFixture(workspace, channel string) string {
	return fmt.Sprintf(`{"guid":%q,"title":"Synthetic OSEE workspace","channels":[{"guid":%q,"name":"osee.co.id","class_name":"LiveChatWeb","status":1}]}`, workspace, channel)
}

func anyChatChatFixture(chat, channel, contact string) string {
	return fmt.Sprintf(`{"guid":%q,"channel":%q,"assigned_to":null,"is_closed":0,"is_archive":0,"mute":0,"source":"livechat","source_id":null,"contact":%s,"created_at":1,"updated_at":2,"last_message_at":2}`, chat, channel, contact)
}

func TestAnyChatScopedMetadataReads(t *testing.T) {
	var paths []string
	client, err := NewAnyChatClient(anyChatTestConfig(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != "api.anychat.one" || request.URL.RawQuery != "" || request.Header.Get("x-api-key") != anyChatTestKey {
			t.Fatal("request does not match documented read contract")
		}
		paths = append(paths, request.URL.Path)
		switch request.URL.Path {
		case "/public/v1/workspace":
			return anyChatTestResponse(request, 200, anyChatWorkspaceFixture(anyChatTestWorkspace, anyChatTestChannel)), nil
		case "/public/v1/chat/" + anyChatTestChat:
			return anyChatTestResponse(request, 200, anyChatChatFixture(anyChatTestChat, anyChatTestChannel, `{"guid":"`+anyChatTestContact+`"}`)), nil
		case "/public/v1/contact/" + anyChatTestContact:
			return anyChatTestResponse(request, 200, `{"guid":"`+anyChatTestContact+`","source":"livechat","source_id":"external-source-ref","created_at":1,"updated_at":2,"email":"omit@example.test","phone":"synthetic-omit"}`), nil
		default:
			t.Fatal("unexpected endpoint")
			return nil, errors.New("unexpected endpoint")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	contact, err := client.ContactForChat(context.Background(), anyChatTestChat, anyChatTestContact)
	if err != nil || contact.GUID != anyChatTestContact || contact.SourceID == nil || *contact.SourceID != "external-source-ref" {
		t.Fatalf("mapped metadata read failed: %v", err)
	}
	if strings.Join(paths, ",") != "/public/v1/workspace,/public/v1/chat/"+anyChatTestChat+",/public/v1/contact/"+anyChatTestContact {
		t.Fatal("read order did not verify scope first")
	}
	projection := fmt.Sprintf("%+v", contact)
	if strings.Contains(projection, "omit@example.test") || strings.Contains(projection, "synthetic-omit") {
		t.Fatal("unneeded personal fields retained")
	}
}

func TestAnyChatFailsClosedBeforeContactRead(t *testing.T) {
	correctWorkspace := anyChatWorkspaceFixture(anyChatTestWorkspace, anyChatTestChannel)
	correctChat := anyChatChatFixture(anyChatTestChat, anyChatTestChannel, `{"guid":"`+anyChatTestContact+`"}`)
	tests := []struct {
		name, workspace, chat, contact string
		maximumRequests                int
	}{
		{"wrong workspace", anyChatWorkspaceFixture(anyChatTestOther, anyChatTestChannel), correctChat, "", 1},
		{"wrong channel", anyChatWorkspaceFixture(anyChatTestWorkspace, anyChatTestOther), correctChat, "", 1},
		{"missing channel", `{"guid":"` + anyChatTestWorkspace + `","channels":[]}`, correctChat, "", 1},
		{"wrong chat reference", correctWorkspace, anyChatChatFixture(anyChatTestOther, anyChatTestChannel, "null"), "", 2},
		{"another brand chat", correctWorkspace, anyChatChatFixture(anyChatTestChat, anyChatTestOther, "null"), "", 2},
		{"unknown contact association", correctWorkspace, anyChatChatFixture(anyChatTestChat, anyChatTestChannel, "null"), "", 2},
		{"other contact association", correctWorkspace, anyChatChatFixture(anyChatTestChat, anyChatTestChannel, `{"guid":"`+anyChatTestOther+`"}`), "", 2},
		{"wrong contact response", correctWorkspace, correctChat, `{"guid":"` + anyChatTestOther + `"}`, 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client, err := NewAnyChatClient(anyChatTestConfig(func(request *http.Request) (*http.Response, error) {
				requests++
				body := test.workspace
				if strings.Contains(request.URL.Path, "/chat/") {
					body = test.chat
				}
				if strings.Contains(request.URL.Path, "/contact/") {
					body = test.contact
				}
				return anyChatTestResponse(request, 200, body), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ContactForChat(context.Background(), anyChatTestChat, anyChatTestContact); !errors.Is(err, ErrAnyChatScope) {
				t.Fatalf("expected scope failure, got %v", err)
			}
			if requests != test.maximumRequests {
				t.Fatalf("unexpected network reads: %d", requests)
			}
		})
	}
}

func TestAnyChatTransportBoundsAndRedaction(t *testing.T) {
	for _, test := range []struct {
		name, body, contentType, retry string
		status                         int
		want                           error
	}{
		{"redirect", "", "application/json", "", 302, ErrAnyChatUnavailable},
		{"unauthorized", anyChatTestKey, "application/json", "", 401, ErrAnyChatUnauthorized},
		{"rate limit", "private vendor error " + anyChatTestKey, "application/json", "7", 429, ErrAnyChatUnavailable},
		{"invalid json", "private vendor error " + anyChatTestKey, "application/json", "", 200, ErrAnyChatResponse},
		{"html", "<html>private</html>", "text/html", "", 200, ErrAnyChatResponse},
		{"oversized", strings.Repeat(" ", anyChatMaxResponseBytes+1), "application/json", "", 200, ErrAnyChatResponse},
		{"trailing data", anyChatWorkspaceFixture(anyChatTestWorkspace, anyChatTestChannel) + "{}", "application/json", "", 200, ErrAnyChatResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			config := anyChatTestConfig(func(request *http.Request) (*http.Response, error) {
				requests++
				if request.URL.Host != "api.anychat.one" {
					t.Fatal("credential sent to wrong host")
				}
				response := anyChatTestResponse(request, test.status, test.body)
				response.Header.Set("Location", "https://untrusted.example.test/collect")
				response.Header.Set("Content-Type", test.contentType)
				response.Header.Set("Retry-After", test.retry)
				return response, nil
			})
			config.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
			client, err := NewAnyChatClient(config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Workspace(context.Background())
			if !errors.Is(err, test.want) || requests != 1 {
				t.Fatalf("unexpected bounded read result: %v (%d requests)", err, requests)
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v %v", client, config, config, err), anyChatTestKey) || strings.Contains(err.Error(), "private") {
				t.Fatal("error or formatter exposed sensitive data")
			}
			if test.retry == "7" {
				var status *AnyChatHTTPError
				if !errors.As(err, &status) || status.RetryAfter != 7*time.Second {
					t.Fatal("retry hint was lost")
				}
			}
		})
	}
	client, _ := NewAnyChatClient(anyChatTestConfig(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + anyChatTestKey)
	}))
	if _, err := client.Workspace(context.Background()); !errors.Is(err, ErrAnyChatUnavailable) || strings.Contains(err.Error(), anyChatTestKey) {
		t.Fatal("transport error not redacted")
	}
}

func TestAnyChatRejectsInvalidConfigAndReferences(t *testing.T) {
	config := anyChatTestConfig(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid reference reached transport")
		return nil, nil
	})
	for _, key := range []string{"", "bad\nkey", "has space", strings.Repeat("x", 4097)} {
		invalid := config
		invalid.APIKey = key
		if _, err := NewAnyChatClient(invalid); !errors.Is(err, ErrAnyChatConfig) {
			t.Fatal("invalid credential accepted")
		}
	}
	client, err := NewAnyChatClient(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{"", "../../contact", anyChatTestChat + "?key=leak", "00000000-0000-0000-0000-000000000000"} {
		if _, err := client.Chat(context.Background(), reference); !errors.Is(err, ErrAnyChatInput) {
			t.Fatal("invalid reference accepted")
		}
	}
	if client.http.Timeout != 15*time.Second {
		t.Fatal("unbounded timeout")
	}
}
