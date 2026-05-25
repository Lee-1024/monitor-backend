package knowledge

import (
	"sort"
	"strings"
)

type DocumentCandidate struct {
	ID       string
	Title    string
	Category string
	Summary  string
	Tags     []string
	Content  string
	URL      string
}

func RankDocuments(query Query, candidates []DocumentCandidate) []Document {
	query = query.WithDefaults()
	terms := queryTerms(query.Text)
	results := make([]Document, 0, len(candidates))
	for _, candidate := range candidates {
		score, fields := scoreCandidate(candidate, terms)
		if score < query.MinScore || score == 0 {
			continue
		}
		url := candidate.URL
		if url == "" {
			url = "/knowledge/" + candidate.ID
		}
		results = append(results, Document{
			ID:            candidate.ID,
			Title:         candidate.Title,
			Category:      candidate.Category,
			Score:         score,
			MatchedFields: fields,
			Snippet:       snippet(candidate),
			URL:           url,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	if len(results) > query.Limit {
		results = results[:query.Limit]
	}
	return results
}

func scoreCandidate(candidate DocumentCandidate, terms []string) (float64, []string) {
	var score float64
	fields := map[string]bool{}
	title := strings.ToLower(candidate.Title)
	summary := strings.ToLower(candidate.Summary)
	content := strings.ToLower(candidate.Content)
	category := strings.ToLower(candidate.Category)
	for _, term := range terms {
		if title == term {
			score += 100
			fields["title"] = true
		}
		if strings.Contains(title, term) {
			score += 50
			fields["title"] = true
		}
		if strings.Contains(summary, term) {
			score += 30
			fields["summary"] = true
		}
		if strings.Contains(category, term) {
			score += 25
			fields["category"] = true
		}
		for _, tag := range candidate.Tags {
			if strings.Contains(strings.ToLower(tag), term) {
				score += 25
				fields["tags"] = true
			}
		}
		if strings.Contains(content, term) {
			score += 10
			fields["content"] = true
		}
	}
	return score, sortedFields(fields)
}

func queryTerms(text string) []string {
	parts := strings.Fields(strings.ToLower(text))
	if len(parts) == 0 && strings.TrimSpace(text) != "" {
		return []string{strings.ToLower(strings.TrimSpace(text))}
	}
	return parts
}

func sortedFields(fields map[string]bool) []string {
	result := make([]string, 0, len(fields))
	for field := range fields {
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}

func snippet(candidate DocumentCandidate) string {
	if strings.TrimSpace(candidate.Summary) != "" {
		return limit(candidate.Summary, 160)
	}
	return limit(candidate.Content, 160)
}

func limit(value string, size int) string {
	value = strings.TrimSpace(value)
	if len(value) <= size {
		return value
	}
	return value[:size] + "..."
}
