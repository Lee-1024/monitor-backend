package knowledge

type Query struct {
	Text     string
	HostID   string
	Intent   string
	Limit    int
	MinScore float64
}

func (q Query) WithDefaults() Query {
	if q.Limit <= 0 {
		q.Limit = 5
	}
	return q
}

type Document struct {
	ID            string
	Title         string
	Category      string
	Score         float64
	MatchedFields []string
	Snippet       string
	URL           string
}
