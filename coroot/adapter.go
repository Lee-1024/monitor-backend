package coroot

import (
	"context"
	"fmt"
	"net/url"
	"path"
)

type Adapter struct {
	client  *Client
	project string
}

func NewAdapter(client *Client, project string) *Adapter {
	return &Adapter{client: client, project: project}
}

func (a *Adapter) Get(ctx context.Context, resource string, query url.Values, target interface{}) error {
	if a == nil || a.client == nil {
		return &APIError{Operation: resource, Message: "coroot is disabled"}
	}
	if query == nil {
		query = url.Values{}
	}
	if a.project != "" && query.Get("project") == "" {
		query.Set("project", a.project)
	}
	if a.project == "" {
		return &APIError{Operation: resource, Message: "coroot project_id is required"}
	}
	project := url.PathEscape(a.project)
	resourcePath := map[string]string{
		"overview":     fmt.Sprintf("/api/project/%s/overview/applications", project),
		"applications": fmt.Sprintf("/api/project/%s/overview/applications", project),
		"topology":     fmt.Sprintf("/api/project/%s/overview/topology", project),
		"nodes":        fmt.Sprintf("/api/project/%s/overview/nodes", project),
		"incidents":    fmt.Sprintf("/api/project/%s/incidents", project),
		"alerts":       fmt.Sprintf("/api/project/%s/alerts", project),
	}[resource]
	if resourcePath == "" {
		switch {
		case len(resource) > len("application:") && resource[:len("application:")] == "application:":
			resourcePath = fmt.Sprintf("/api/project/%s/app/%s", project, url.PathEscape(resource[len("application:"):]))
		case len(resource) > len("incident:") && resource[:len("incident:")] == "incident:":
			resourcePath = fmt.Sprintf("/api/project/%s/incident/%s", project, url.PathEscape(resource[len("incident:"):]))
		case len(resource) > len("node:") && resource[:len("node:")] == "node:":
			resourcePath = fmt.Sprintf("/api/project/%s/node/%s", project, url.PathEscape(resource[len("node:"):]))
		}
	}
	if resourcePath == "" {
		return &APIError{Operation: resource, Message: "unsupported Coroot resource"}
	}
	return a.client.Get(ctx, resource, path.Clean(resourcePath), query, target)
}
