package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type corootResourceResponse struct {
	Enabled   bool        `json:"enabled"`
	Available bool        `json:"available"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	CheckedAt time.Time   `json:"checked_at"`
	Stale     bool        `json:"stale,omitempty"`
	CachedAt  *time.Time  `json:"cached_at,omitempty"`
}

func (s *APIServer) corootResource(resource string, c *gin.Context) {
	if resource == "deep-links" {
		if s.corootAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, Response{Code: http.StatusServiceUnavailable, Message: "Coroot 未启用"})
			return
		}
		application := c.Query("application")
		if application == "" {
			c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "缺少 application 参数"})
			return
		}
		base := s.config.Coroot.PublicBaseURL
		if base == "" {
			base = "/coroot/"
		}
		base = strings.TrimRight(base, "/")
		id := url.PathEscape(application)
		links := map[string]string{
			"application": base + "/p/" + url.PathEscape(s.config.Coroot.ProjectID) + "/overview",
			"traces":      base + "/p/" + url.PathEscape(s.config.Coroot.ProjectID) + "/app/" + id + "/tracing",
			"logs":        base + "/p/" + url.PathEscape(s.config.Coroot.ProjectID) + "/app/" + id + "/logs",
			"profile":     base + "/p/" + url.PathEscape(s.config.Coroot.ProjectID) + "/app/" + id + "/profiling",
		}
		c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: corootResourceResponse{Enabled: true, Available: true, CheckedAt: time.Now(), Data: links}})
		return
	}
	if s.corootAdapter == nil {
		c.JSON(http.StatusServiceUnavailable, Response{Code: http.StatusServiceUnavailable, Message: "Coroot 未启用", Data: corootResourceResponse{CheckedAt: time.Now(), Error: "Coroot 未启用"}})
		return
	}
	query := url.Values{}
	for _, key := range []string{"page", "page_size", "search", "namespace", "status", "resolved"} {
		if value := c.Query(key); value != "" {
			query.Set(key, value)
		}
	}
	if pageSize, _ := strconv.Atoi(query.Get("page_size")); pageSize > 200 {
		query.Set("page_size", "200")
	}
	var data interface{}
	cacheKey := "project:" + s.config.Coroot.ProjectID + ":" + resource + ":" + query.Encode()
	if s.corootCache != nil {
		var cached interface{}
		if hit, cachedAt, err := s.corootCache.Get(c.Request.Context(), cacheKey, &cached); err == nil && hit {
			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: corootResourceResponse{Enabled: true, Available: true, Data: cached, CheckedAt: time.Now(), CachedAt: &cachedAt}})
			return
		}
	}
	if err := s.corootAdapter.Get(c.Request.Context(), resource, query, &data); err != nil {
		c.JSON(http.StatusBadGateway, Response{Code: http.StatusBadGateway, Message: "Coroot 暂时不可用", Data: corootResourceResponse{Enabled: true, CheckedAt: time.Now(), Error: "Coroot 暂时不可用"}})
		return
	}
	ttl := 15 * time.Second
	switch resource {
	case "overview":
		ttl = 10 * time.Second
	case "topology":
		ttl = 30 * time.Second
	case "incidents", "alerts":
		ttl = 5 * time.Second
	}
	if s.corootCache != nil {
		_ = s.corootCache.Set(c.Request.Context(), cacheKey, data, ttl)
	}
	c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: corootResourceResponse{Enabled: true, Available: true, Data: data, CheckedAt: time.Now()}})
}

func (s *APIServer) corootStatus(c *gin.Context) {
	if s.corootAdapter == nil {
		c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: corootResourceResponse{CheckedAt: time.Now(), Error: "Coroot 未启用"}})
		return
	}
	var data interface{}
	err := s.corootAdapter.Get(c.Request.Context(), "overview", nil, &data)
	if err != nil {
		c.JSON(http.StatusBadGateway, Response{Code: http.StatusBadGateway, Message: "Coroot 暂时不可用", Data: corootResourceResponse{Enabled: true, CheckedAt: time.Now(), Error: "Coroot 暂时不可用"}})
		return
	}
	c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: corootResourceResponse{Enabled: true, Available: true, Data: data, CheckedAt: time.Now()}})
}
