package coroot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("coroot base_url is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid coroot base_url")
	}
	return &Client{baseURL: baseURL, apiKey: strings.TrimSpace(cfg.APIKey), http: &http.Client{Timeout: cfg.EffectiveTimeout()}}, nil
}

func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) Get(ctx context.Context, operation, path string, query url.Values, target interface{}) error {
	requestURL := c.baseURL + "/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return &APIError{Operation: operation, Message: "create request"}
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("X-API-Key", c.apiKey)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return &APIError{Operation: operation, Message: err.Error()}
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return &APIError{Operation: operation, Status: response.StatusCode}
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(target); err != nil {
		return &APIError{Operation: operation, Message: "decode response"}
	}
	return nil
}
