package knowledge

import "testing"

func TestRankDocumentsRanksTitleAboveContent(t *testing.T) {
	docs := []DocumentCandidate{
		{ID: "1", Title: "Generic Linux guide", Content: "memory high troubleshooting"},
		{ID: "2", Title: "Memory high SOP", Content: "generic content"},
	}

	results := RankDocuments(Query{Text: "memory high", Limit: 5}, docs)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].ID != "2" {
		t.Fatalf("expected title match first, got %#v", results)
	}
}

func TestRankDocumentsReturnsMatchedFields(t *testing.T) {
	docs := []DocumentCandidate{
		{ID: "1", Title: "Linux", Summary: "memory pressure", Tags: []string{"memory"}},
	}

	results := RankDocuments(Query{Text: "memory", Limit: 5}, docs)

	if len(results) != 1 {
		t.Fatalf("expected result, got none")
	}
	if len(results[0].MatchedFields) == 0 {
		t.Fatalf("expected matched fields, got %#v", results[0])
	}
}

func TestRankDocumentsAppliesLimitAndMinimumScore(t *testing.T) {
	docs := []DocumentCandidate{
		{ID: "1", Title: "memory"},
		{ID: "2", Content: "memory"},
		{ID: "3", Title: "network"},
	}

	results := RankDocuments(Query{Text: "memory", Limit: 1, MinScore: 20}, docs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %#v", results)
	}
	if results[0].ID != "1" {
		t.Fatalf("expected highest scoring result, got %#v", results[0])
	}
}
