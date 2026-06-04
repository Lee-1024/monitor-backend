package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (s *APIServer) listServerProbeTargets(c *gin.Context) {
	targets, err := s.storage.ListServerProbeTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success", Data: targets})
}

func (s *APIServer) createServerProbeTarget(c *gin.Context) {
	var target ServerProbeTargetInfo
	if err := c.ShouldBindJSON(&target); err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}
	created, err := s.storage.CreateServerProbeTarget(&target)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success", Data: created})
}

func (s *APIServer) updateServerProbeTarget(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	var target ServerProbeTargetInfo
	if err := c.ShouldBindJSON(&target); err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}
	updated, err := s.storage.UpdateServerProbeTarget(id, &target)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success", Data: updated})
}

func (s *APIServer) deleteServerProbeTarget(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	if err := s.storage.DeleteServerProbeTarget(id); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success"})
}

func (s *APIServer) testServerProbeTarget(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	result, err := s.storage.TestServerProbeTarget(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success", Data: result})
}

func (s *APIServer) listServerProbeResults(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	results, err := s.storage.ListServerProbeResults(id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "success", Data: results})
}

func parseUintParam(c *gin.Context, name string) (uint, bool) {
	value, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: "invalid " + name})
		return 0, false
	}
	return uint(value), true
}
