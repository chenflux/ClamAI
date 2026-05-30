package main

import (
	"testing"
)

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == "" {
		t.Error("generateID returned empty string")
	}
	if id1 == id2 {
		t.Error("generateID returned duplicate IDs")
	}
	if len(id1) != 24 {
		t.Errorf("generateID length = %d, want 24 (12 bytes hex)", len(id1))
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key1 := generateRandomKey(32)
	key2 := generateRandomKey(32)
	if key1 == "" {
		t.Error("generateRandomKey returned empty string")
	}
	if key1 == key2 {
		t.Error("generateRandomKey returned duplicate keys")
	}
	if len(key1) != 64 {
		t.Errorf("generateRandomKey(32) length = %d, want 64 (32 bytes hex)", len(key1))
	}
}

func TestNewRequestStats(t *testing.T) {
	stats := NewRequestStats()
	if stats == nil {
		t.Fatal("NewRequestStats returned nil")
	}
	if stats.RequestsByProvider == nil {
		t.Error("RequestsByProvider map should be initialized")
	}
	if stats.RequestsByModel == nil {
		t.Error("RequestsByModel map should be initialized")
	}
	if stats.DailyStats == nil {
		t.Error("DailyStats map should be initialized")
	}
	if stats.TokensByProvider == nil {
		t.Error("TokensByProvider map should be initialized")
	}
}

func TestRequestStatsToJSON(t *testing.T) {
	stats := NewRequestStats()
	stats.TotalRequests.Store(42)
	stats.InputTokens.Store(100)

	j := stats.ToJSON()
	if j.TotalRequests != 42 {
		t.Errorf("TotalRequests = %d, want 42", j.TotalRequests)
	}
	if j.InputTokens != 100 {
		t.Errorf("InputTokens = %d, want 100", j.InputTokens)
	}
	if j.RequestsByProvider == nil {
		t.Error("RequestsByProvider should not be nil in JSON output")
	}
}

func TestRequestStatsLoadFromJSON(t *testing.T) {
	stats := NewRequestStats()
	j := &RequestStatsForJSON{
		TotalRequests:   10,
		SuccessRequests: 8,
		ErrorRequests:   2,
		RequestsByProvider: map[string]int64{"openai": 5},
	}
	stats.LoadFromJSON(j)
	if stats.TotalRequests.Load() != 10 {
		t.Errorf("TotalRequests = %d, want 10", stats.TotalRequests.Load())
	}
	if stats.RequestsByProvider["openai"] != 5 {
		t.Errorf("RequestsByProvider[openai] = %d, want 5", stats.RequestsByProvider["openai"])
	}
}

func TestLogBuffer(t *testing.T) {
	buf := NewLogBuffer(3)
	buf.Add(&RequestLog{ID: 1})
	buf.Add(&RequestLog{ID: 2})
	buf.Add(&RequestLog{ID: 3})
	buf.Add(&RequestLog{ID: 4})
	if buf.Count() != 3 {
		t.Errorf("Count = %d, want 3", buf.Count())
	}
	recent := buf.GetRecent(2)
	if len(recent) != 2 {
		t.Errorf("GetRecent(2) = %d items, want 2", len(recent))
	}
	if recent[0].ID != 4 {
		t.Errorf("most recent ID = %d, want 4", recent[0].ID)
	}
	all := buf.GetAll()
	if len(all) != 3 {
		t.Errorf("GetAll() = %d items, want 3", len(all))
	}
}

func TestLogBuffer_GetRecentOverflow(t *testing.T) {
	buf := NewLogBuffer(5)
	buf.Add(&RequestLog{ID: 1})
	recent := buf.GetRecent(10)
	if len(recent) != 1 {
		t.Errorf("GetRecent(10) with 1 entry = %d items, want 1", len(recent))
	}
}
