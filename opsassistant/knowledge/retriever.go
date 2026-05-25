package knowledge

import "context"

type Retriever interface {
	Retrieve(ctx context.Context, query Query) ([]Document, error)
}
