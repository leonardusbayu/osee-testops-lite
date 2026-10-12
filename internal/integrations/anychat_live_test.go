package integrations

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt-in metadata preflight only. It neither reads participants nor creates
// credentials. The local credential file must be explicitly supplied by staff.
func TestAnyChatLiveMetadataPreflight(t *testing.T) {
	path := os.Getenv("OSEE_ANYCHAT_PREFLIGHT_FILE")
	if path == "" {
		t.Skip("live metadata preflight is not enabled")
	}
	var saved struct {
		APIKey        string `json:"apiKey"`
		KeyName       string `json:"keyName"`
		AccountSite   string `json:"accountSite"`
		Brand         string `json:"brand"`
		WorkspaceGUID string `json:"workspaceGUID,omitempty"`
		ChannelGUID   string `json:"channelGUID,omitempty"`
		ChannelName   string `json:"channelName,omitempty"`
		ChannelClass  string `json:"channelClass,omitempty"`
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16*1024 || json.Unmarshal(data, &saved) != nil || !anyChatCredential(saved.APIKey) || saved.Brand != "osee.co.id" {
		t.Fatal("local metadata preflight configuration unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The bootstrap request is only /workspace. Its provisional GUIDs are never
	// accepted as scope; actual metadata must match the explicitly requested brand.
	client, err := NewAnyChatClient(AnyChatConfig{APIKey: saved.APIKey, WorkspaceGUID: anyChatTestWorkspace, ChannelGUID: anyChatTestChannel})
	if err != nil {
		t.Fatal(err)
	}
	var workspace AnyChatWorkspace
	if err := client.read(ctx, "/workspace", &workspace); err != nil {
		t.Fatal(err)
	}
	if !anyChatGUID(workspace.GUID) || workspace.Channels == nil || len(workspace.Channels) > 1000 {
		t.Fatal(ErrAnyChatResponse)
	}
	var matching []AnyChatChannel
	for _, channel := range workspace.Channels {
		if !anyChatGUID(channel.GUID) {
			t.Fatal(ErrAnyChatResponse)
		}
		if strings.EqualFold(channel.Name, "osee.co.id") {
			t.Logf("osee.co.id candidate channel=%s label=%q class=%q", channel.GUID, channel.Name, channel.ClassName)
			if channel.ClassName == "LiveChatWeb" {
				matching = append(matching, channel)
			}
		}
	}
	if len(matching) != 1 {
		t.Fatal("exact osee.co.id web channel requires staff reconciliation")
	}
	channel := matching[0]
	if (saved.WorkspaceGUID != "" && !strings.EqualFold(saved.WorkspaceGUID, workspace.GUID)) || (saved.ChannelGUID != "" && !strings.EqualFold(saved.ChannelGUID, channel.GUID)) {
		t.Fatal(ErrAnyChatScope)
	}
	client, err = NewAnyChatClient(AnyChatConfig{APIKey: saved.APIKey, WorkspaceGUID: workspace.GUID, ChannelGUID: channel.GUID})
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := client.Workspace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	saved.WorkspaceGUID, saved.ChannelGUID = strings.ToLower(confirmed.GUID), strings.ToLower(channel.GUID)
	saved.ChannelName, saved.ChannelClass = channel.Name, channel.ClassName
	output, err := json.MarshalIndent(saved, "", "  ")
	if err != nil || os.WriteFile(path, output, 0600) != nil {
		t.Fatal("could not preserve local metadata binding")
	}
	t.Logf("metadata preflight verified workspace=%s channel=%s label=%q channel_count=%d", confirmed.GUID, channel.GUID, channel.Name, len(confirmed.Channels))
}
