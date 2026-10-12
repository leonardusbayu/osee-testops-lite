package integrations

import (
	"bytes"
	"encoding/json"
	"strings"

	"osee-testops-lite/internal/core"
)

type syncRemoteTask struct {
	ID string `json:"id"`
	DartTask
}

func syncObject(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxDartResponse {
		return nil, ErrDartSyncUncertain
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrDartSyncUncertain
	}
	if _, ok := fields["id"]; ok {
		return raw, nil
	}
	for _, key := range []string{"item", "task"} {
		if nested, ok := fields[key]; ok {
			return nested, nil
		}
	}
	return nil, ErrDartSyncUncertain
}

func decodeSyncID(raw json.RawMessage) (string, error) {
	object, err := syncObject(raw)
	if err != nil {
		return "", err
	}
	var task struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(object, &task) != nil || !dartID(task.ID) {
		return "", ErrDartSyncUncertain
	}
	return task.ID, nil
}
func decodeSyncTask(raw json.RawMessage) (syncRemoteTask, error) {
	object, err := syncObject(raw)
	if err != nil {
		return syncRemoteTask{}, err
	}
	var task syncRemoteTask
	if json.Unmarshal(object, &task) != nil || !dartID(task.ID) {
		return task, ErrDartSyncUncertain
	}
	return task, nil
}

func decodeSyncList(raw json.RawMessage, id core.ID) ([]syncRemoteTask, bool, error) {
	if len(raw) == 0 || len(raw) > maxDartResponse {
		return nil, false, ErrDartSyncUncertain
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false, ErrDartSyncUncertain
	}
	var items []json.RawMessage
	arrayFound := false
	for _, key := range []string{"results", "tasks", "items"} {
		if value, ok := fields[key]; ok {
			if arrayFound || json.Unmarshal(value, &items) != nil {
				return nil, false, ErrDartSyncUncertain
			}
			arrayFound = true
		}
	}
	if !arrayFound {
		return nil, false, ErrDartSyncUncertain
	}
	complete, incomplete := false, false
	if next, ok := fields["nextToolCall"]; ok {
		if bytes.Equal(bytes.TrimSpace(next), []byte("null")) {
			complete = true
		} else {
			incomplete = true
		}
	}
	if total, ok := fields["total"]; ok {
		var count int
		if json.Unmarshal(total, &count) != nil || count < 0 || count < len(items) {
			return nil, false, ErrDartSyncUncertain
		}
		if count == len(items) {
			complete = true
		} else {
			incomplete = true
		}
	}
	if more, ok := fields["has_more"]; ok {
		var remains bool
		if json.Unmarshal(more, &remains) != nil {
			return nil, false, ErrDartSyncUncertain
		}
		if remains {
			incomplete = true
		} else {
			complete = true
		}
	}
	for _, key := range []string{"next_cursor", "next"} {
		if next, ok := fields[key]; ok && !bytes.Equal(bytes.TrimSpace(next), []byte("null")) && !bytes.Equal(bytes.TrimSpace(next), []byte(`""`)) {
			incomplete = true
		}
	}
	complete = complete && !incomplete
	matches := []syncRemoteTask{}
	seen := map[string]bool{}
	for _, item := range items {
		task, err := decodeSyncTask(item)
		if err != nil {
			return nil, false, err
		}
		if seen[task.ID] {
			return nil, false, ErrDartSyncUncertain
		}
		seen[task.ID] = true
		if strings.Contains(normalizeDartMarkdown(task.Description), syncMarker(id)) && !hasSyncMarker(task.Description, id) {
			return nil, false, ErrDartSyncUncertain
		}
		if hasSyncMarker(task.Description, id) {
			matches = append(matches, task)
		}
	}
	return matches, complete, nil
}
