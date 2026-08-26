package coroot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientGetDecodesJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/apps" || r.URL.Query().Get("project") != "default" {
			t.Fatalf("unexpected request: %s", r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("X-API-Key") != "test-key" {
			t.Fatalf("missing API key headers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"demo"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Name string `json:"name"`
	}
	err = client.Get(context.Background(), "apps", "/api/v1/apps", url.Values{"project": {"default"}}, &result)
	if err != nil || result.Name != "demo" {
		t.Fatalf("unexpected result: %#v, %v", result, err)
	}
}

func TestClientRejectsNonJSONAndNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/not-found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid"))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL})
	var result map[string]interface{}
	if err := client.Get(context.Background(), "missing", "/not-found", nil, &result); err == nil {
		t.Fatal("expected status error")
	}
	if err := client.Get(context.Background(), "invalid", "/invalid", nil, &result); err == nil {
		t.Fatal("expected decode error")
	}
}
