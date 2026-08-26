package coroot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAdapterTopologyUsesMapView(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/project/demo/overview/map" {
			t.Fatalf("unexpected topology path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"map":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAdapter(client, "demo")
	var response map[string]interface{}
	if err := adapter.Get(context.Background(), "topology", url.Values{}, &response); err != nil {
		t.Fatal(err)
	}
}
