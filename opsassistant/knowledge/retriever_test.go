package knowledge

import "testing"

func TestDocumentResultShape(t *testing.T) {
	doc := Document{
		ID:            "12",
		Title:         "Linux memory troubleshooting",
		Category:      "Linux",
		Score:         0.86,
		MatchedFields: []string{"title", "tags"},
		Snippet:       "free, top, ps aux --sort=-%mem",
		URL:           "/knowledge/12",
	}

	if doc.ID != "12" || doc.URL != "/knowledge/12" || len(doc.MatchedFields) != 2 {
		t.Fatalf("unexpected document shape: %#v", doc)
	}
}

func TestQueryDefaults(t *testing.T) {
	query := Query{Text: "memory high"}
	normalized := query.WithDefaults()

	if normalized.Limit != 5 {
		t.Fatalf("expected default limit 5, got %d", normalized.Limit)
	}
	if normalized.MinScore != 0 {
		t.Fatalf("expected default min score 0, got %f", normalized.MinScore)
	}
}
