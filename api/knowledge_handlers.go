// ============================================
// 文件: api/knowledge_handlers.go
// 知识库相关API处理
// ============================================
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// KnowledgeBaseInfo 知识库基础信息
type KnowledgeBaseInfo struct {
	ID          uint      `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	Tags        []string  `json:"tags"`
	Content     string    `json:"content"`
	Summary     string    `json:"summary"`
	Author      string    `json:"author"`
	ViewCount   int       `json:"view_count"`
	LikeCount   int       `json:"like_count"`
	IsPublished bool      `json:"is_published"`
	Metadata    map[string]string `json:"metadata"`
}

// TroubleshootingGuideInfo 故障处理知识库信息
type TroubleshootingGuideInfo struct {
	KnowledgeBaseInfo `json:",inline"`
	ProblemType       string   `json:"problem_type"`
	Severity          string   `json:"severity"`
	Symptoms          []string `json:"symptoms"`
	RootCauses        []string `json:"root_causes"`
	Solutions         []string `json:"solutions"`
	PreventionTips    []string `json:"prevention_tips"`
	RelatedCases      []string `json:"related_cases"`
}

// BestPracticeInfo 最佳实践文档信息
type BestPracticeInfo struct {
	KnowledgeBaseInfo `json:",inline"`
	Domain            string   `json:"domain"`
	Applicability     string   `json:"applicability"`
	Benefits          []string `json:"benefits"`
	Implementation    []string `json:"implementation"`
	References        []string `json:"references"`
}

// CaseStudyInfo 故障案例库信息
type CaseStudyInfo struct {
	KnowledgeBaseInfo `json:",inline"`
	IncidentDate      time.Time  `json:"incident_date"`
	ResolvedDate      *time.Time `json:"resolved_date,omitempty"`
	HostID            string     `json:"host_id"`
	Hostname          string     `json:"hostname"`
	ProblemType       string     `json:"problem_type"`
	Severity          string     `json:"severity"`
	Impact            string     `json:"impact"`
	Timeline          string     `json:"timeline"`
	Resolution        string     `json:"resolution"`
	LessonsLearned    string     `json:"lessons_learned"`
	RelatedGuides     []string `json:"related_guides"`
}

// 获取故障处理知识库列表
func (s *APIServer) listTroubleshootingGuides(c *gin.Context) {
	problemType := c.Query("problem_type")
	severity := c.Query("severity")
	keyword := c.Query("keyword")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	// 获取数据库连接
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	query := db.Table("troubleshooting_guides").Where("is_published = ?", true)

	if problemType != "" {
		query = query.Where("problem_type = ?", problemType)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if keyword != "" {
		query = query.Where("title LIKE ? OR content LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var total int64
	query.Count(&total)

	// 使用map来接收数据，然后转换为Info类型
	var guides []map[string]interface{}
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&guides).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get troubleshooting guides: " + err.Error(),
		})
		return
	}

	result := make([]TroubleshootingGuideInfo, 0, len(guides))
	for _, g := range guides {
		info := convertMapToTroubleshootingGuideInfo(g)
		result = append(result, info)
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"items": result,
			"total": total,
			"page":  page,
			"page_size": pageSize,
		},
	})
}

// 获取故障处理知识库详情
func (s *APIServer) getTroubleshootingGuide(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var guide map[string]interface{}
	if err := db.Table("troubleshooting_guides").Where("id = ?", id).First(&guide).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Troubleshooting guide not found",
		})
		return
	}

	// 增加查看次数
	if viewCount, ok := guide["view_count"].(int); ok {
		db.Table("troubleshooting_guides").Where("id = ?", id).Update("view_count", viewCount+1)
		guide["view_count"] = viewCount + 1
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToTroubleshootingGuideInfo(guide),
	})
}

// 创建故障处理知识库
func (s *APIServer) createTroubleshootingGuide(c *gin.Context) {
	var req TroubleshootingGuideInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	// 构建插入数据
	guideData := map[string]interface{}{
		"title":          req.Title,
		"category":       "troubleshooting",
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"problem_type":   req.ProblemType,
		"severity":       req.Severity,
		"symptoms":       req.Symptoms,
		"root_causes":    req.RootCauses,
		"solutions":      req.Solutions,
		"prevention_tips": req.PreventionTips,
		"related_cases":  req.RelatedCases,
		"created_at":     time.Now(),
		"updated_at":     time.Now(),
	}

	if err := db.Table("troubleshooting_guides").Create(&guideData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create troubleshooting guide: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToTroubleshootingGuideInfo(guideData),
	})
}

// 更新故障处理知识库
func (s *APIServer) updateTroubleshootingGuide(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var guide map[string]interface{}
	if err := db.Table("troubleshooting_guides").Where("id = ?", id).First(&guide).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Troubleshooting guide not found",
		})
		return
	}

	var req TroubleshootingGuideInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 更新数据
	updates := map[string]interface{}{
		"title":          req.Title,
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"problem_type":   req.ProblemType,
		"severity":       req.Severity,
		"symptoms":       req.Symptoms,
		"root_causes":    req.RootCauses,
		"solutions":      req.Solutions,
		"prevention_tips": req.PreventionTips,
		"related_cases":  req.RelatedCases,
		"updated_at":     time.Now(),
	}

	if err := db.Table("troubleshooting_guides").Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update troubleshooting guide: " + err.Error(),
		})
		return
	}

	// 获取更新后的数据
	var updatedGuide map[string]interface{}
	db.Table("troubleshooting_guides").Where("id = ?", id).First(&updatedGuide)

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToTroubleshootingGuideInfo(updatedGuide),
	})
}

// 删除故障处理知识库
func (s *APIServer) deleteTroubleshootingGuide(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}
	
	if err := db.Table("troubleshooting_guides").Where("id = ?", id).Delete(nil).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete troubleshooting guide: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// 获取最佳实践文档列表
func (s *APIServer) listBestPractices(c *gin.Context) {
	domain := c.Query("domain")
	keyword := c.Query("keyword")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	query := db.Table("best_practices").Where("is_published = ?", true)

	if domain != "" {
		query = query.Where("domain = ?", domain)
	}
	if keyword != "" {
		query = query.Where("title LIKE ? OR content LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var total int64
	query.Count(&total)

	var practices []map[string]interface{}
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&practices).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get best practices: " + err.Error(),
		})
		return
	}

	result := make([]BestPracticeInfo, 0, len(practices))
	for _, p := range practices {
		result = append(result, convertMapToBestPracticeInfo(p))
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"items": result,
			"total": total,
			"page":  page,
			"page_size": pageSize,
		},
	})
}

// 获取最佳实践文档详情
func (s *APIServer) getBestPractice(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var practice map[string]interface{}
	if err := db.Table("best_practices").Where("id = ?", id).First(&practice).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Best practice not found",
		})
		return
	}

	if viewCount, ok := practice["view_count"].(int); ok {
		db.Table("best_practices").Where("id = ?", id).Update("view_count", viewCount+1)
		practice["view_count"] = viewCount + 1
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToBestPracticeInfo(practice),
	})
}

// 创建最佳实践文档
func (s *APIServer) createBestPractice(c *gin.Context) {
	var req BestPracticeInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	practiceData := map[string]interface{}{
		"title":          req.Title,
		"category":       "best_practice",
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"domain":         req.Domain,
		"applicability":  req.Applicability,
		"benefits":       req.Benefits,
		"implementation": req.Implementation,
		"references":     req.References,
		"created_at":     time.Now(),
		"updated_at":     time.Now(),
	}

	if err := db.Table("best_practices").Create(&practiceData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create best practice: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToBestPracticeInfo(practiceData),
	})
}

// 更新最佳实践文档
func (s *APIServer) updateBestPractice(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var practice map[string]interface{}
	if err := db.Table("best_practices").Where("id = ?", id).First(&practice).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Best practice not found",
		})
		return
	}

	var req BestPracticeInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	updates := map[string]interface{}{
		"title":          req.Title,
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"domain":         req.Domain,
		"applicability":  req.Applicability,
		"benefits":       req.Benefits,
		"implementation": req.Implementation,
		"references":     req.References,
		"updated_at":     time.Now(),
	}

	if err := db.Table("best_practices").Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update best practice: " + err.Error(),
		})
		return
	}

	var updatedPractice map[string]interface{}
	db.Table("best_practices").Where("id = ?", id).First(&updatedPractice)

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToBestPracticeInfo(updatedPractice),
	})
}

// 删除最佳实践文档
func (s *APIServer) deleteBestPractice(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}
	
	if err := db.Table("best_practices").Where("id = ?", id).Delete(nil).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete best practice: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// 获取故障案例库列表
func (s *APIServer) listCaseStudies(c *gin.Context) {
	problemType := c.Query("problem_type")
	severity := c.Query("severity")
	hostID := c.Query("host_id")
	keyword := c.Query("keyword")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	query := db.Table("case_studies").Where("is_published = ?", true)

	if problemType != "" {
		query = query.Where("problem_type = ?", problemType)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if keyword != "" {
		query = query.Where("title LIKE ? OR content LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var total int64
	query.Count(&total)

	var cases []map[string]interface{}
	offset := (page - 1) * pageSize
	if err := query.Order("incident_date DESC").Offset(offset).Limit(pageSize).Find(&cases).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get case studies: " + err.Error(),
		})
		return
	}

	result := make([]CaseStudyInfo, 0, len(cases))
	for _, cs := range cases {
		result = append(result, convertMapToCaseStudyInfo(cs))
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"items": result,
			"total": total,
			"page":  page,
			"page_size": pageSize,
		},
	})
}

// 获取故障案例库详情
func (s *APIServer) getCaseStudy(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var caseStudy map[string]interface{}
	if err := db.Table("case_studies").Where("id = ?", id).First(&caseStudy).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Case study not found",
		})
		return
	}

	if viewCount, ok := caseStudy["view_count"].(int); ok {
		db.Table("case_studies").Where("id = ?", id).Update("view_count", viewCount+1)
		caseStudy["view_count"] = viewCount + 1
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToCaseStudyInfo(caseStudy),
	})
}

// 创建故障案例库
func (s *APIServer) createCaseStudy(c *gin.Context) {
	var req CaseStudyInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	caseStudyData := map[string]interface{}{
		"title":          req.Title,
		"category":       "case_study",
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"incident_date":  req.IncidentDate,
		"resolved_date":  req.ResolvedDate,
		"host_id":        req.HostID,
		"hostname":       req.Hostname,
		"problem_type":   req.ProblemType,
		"severity":       req.Severity,
		"impact":         req.Impact,
		"timeline":       req.Timeline,
		"resolution":     req.Resolution,
		"lessons_learned": req.LessonsLearned,
		"related_guides": req.RelatedGuides,
		"created_at":     time.Now(),
		"updated_at":     time.Now(),
	}

	if err := db.Table("case_studies").Create(&caseStudyData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create case study: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToCaseStudyInfo(caseStudyData),
	})
}

// 更新故障案例库
func (s *APIServer) updateCaseStudy(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var caseStudy map[string]interface{}
	if err := db.Table("case_studies").Where("id = ?", id).First(&caseStudy).Error; err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Case study not found",
		})
		return
	}

	var req CaseStudyInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	updates := map[string]interface{}{
		"title":          req.Title,
		"tags":           req.Tags,
		"content":        req.Content,
		"summary":        req.Summary,
		"author":         req.Author,
		"is_published":   req.IsPublished,
		"metadata":       req.Metadata,
		"incident_date":  req.IncidentDate,
		"resolved_date":  req.ResolvedDate,
		"host_id":        req.HostID,
		"hostname":       req.Hostname,
		"problem_type":   req.ProblemType,
		"severity":       req.Severity,
		"impact":         req.Impact,
		"timeline":       req.Timeline,
		"resolution":     req.Resolution,
		"lessons_learned": req.LessonsLearned,
		"related_guides": req.RelatedGuides,
		"updated_at":     time.Now(),
	}

	if err := db.Table("case_studies").Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update case study: " + err.Error(),
		})
		return
	}

	var updatedCaseStudy map[string]interface{}
	db.Table("case_studies").Where("id = ?", id).First(&updatedCaseStudy)

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    convertMapToCaseStudyInfo(updatedCaseStudy),
	})
}

// 删除故障案例库
func (s *APIServer) deleteCaseStudy(c *gin.Context) {
	id := c.Param("id")
	
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}
	
	if err := db.Table("case_studies").Where("id = ?", id).Delete(nil).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete case study: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// LLM搜索知识库
func (s *APIServer) searchKnowledgeBase(c *gin.Context) {
	query := c.Query("q")
	category := c.DefaultQuery("category", "") // troubleshooting/best_practice/case_study

	if query == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Search query is required",
		})
		return
	}

	// 检查LLM是否可用
	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "LLM service not available",
		})
		return
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// 通过反射调用 StreamKnowledgeSearch 方法
	type ClientGetter interface {
		GetClient() interface{}
	}
	
	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}

	if actualClient == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get LLM client",
		})
		return
	}

	// 调用流式方法
	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamKnowledgeSearch")
	if !streamMethod.IsValid() {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "LLM client does not support knowledge search streaming",
		})
		return
	}

	log.Printf("[API] 使用流式知识库搜索: %s", query)
	results := streamMethod.Call([]reflect.Value{
		reflect.ValueOf(query),
		reflect.ValueOf(category),
		reflect.ValueOf(c.Writer),
	})

	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			log.Printf("[API] 流式知识库搜索失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
		}
	}
}

// 辅助函数：从map转换
func convertMapToTroubleshootingGuideInfo(m map[string]interface{}) TroubleshootingGuideInfo {
	info := TroubleshootingGuideInfo{
		KnowledgeBaseInfo: convertMapToKnowledgeBaseInfo(m),
	}
	if v, ok := m["problem_type"].(string); ok {
		info.ProblemType = v
	}
	if v, ok := m["severity"].(string); ok {
		info.Severity = v
	}
	// 处理JSON字段
	if v, ok := m["symptoms"].([]interface{}); ok {
		info.Symptoms = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["root_causes"].([]interface{}); ok {
		info.RootCauses = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["solutions"].([]interface{}); ok {
		info.Solutions = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["prevention_tips"].([]interface{}); ok {
		info.PreventionTips = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["related_cases"].([]interface{}); ok {
		info.RelatedCases = convertInterfaceSliceToStringSlice(v)
	}
	return info
}

func convertMapToBestPracticeInfo(m map[string]interface{}) BestPracticeInfo {
	info := BestPracticeInfo{
		KnowledgeBaseInfo: convertMapToKnowledgeBaseInfo(m),
	}
	if v, ok := m["domain"].(string); ok {
		info.Domain = v
	}
	if v, ok := m["applicability"].(string); ok {
		info.Applicability = v
	}
	if v, ok := m["benefits"].([]interface{}); ok {
		info.Benefits = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["implementation"].([]interface{}); ok {
		info.Implementation = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["references"].([]interface{}); ok {
		info.References = convertInterfaceSliceToStringSlice(v)
	}
	return info
}

func convertMapToCaseStudyInfo(m map[string]interface{}) CaseStudyInfo {
	info := CaseStudyInfo{
		KnowledgeBaseInfo: convertMapToKnowledgeBaseInfo(m),
	}
	if v, ok := m["incident_date"].(time.Time); ok {
		info.IncidentDate = v
	} else if v, ok := m["incident_date"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.IncidentDate = t
		}
	}
	if v, ok := m["resolved_date"].(*time.Time); ok {
		info.ResolvedDate = v
	} else if v, ok := m["resolved_date"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.ResolvedDate = &t
		}
	}
	if v, ok := m["host_id"].(string); ok {
		info.HostID = v
	}
	if v, ok := m["hostname"].(string); ok {
		info.Hostname = v
	}
	if v, ok := m["problem_type"].(string); ok {
		info.ProblemType = v
	}
	if v, ok := m["severity"].(string); ok {
		info.Severity = v
	}
	if v, ok := m["impact"].(string); ok {
		info.Impact = v
	}
	if v, ok := m["timeline"].(string); ok {
		info.Timeline = v
	}
	if v, ok := m["resolution"].(string); ok {
		info.Resolution = v
	}
	if v, ok := m["lessons_learned"].(string); ok {
		info.LessonsLearned = v
	}
	if v, ok := m["related_guides"].([]interface{}); ok {
		info.RelatedGuides = convertInterfaceSliceToStringSlice(v)
	}
	return info
}

func convertMapToKnowledgeBaseInfo(m map[string]interface{}) KnowledgeBaseInfo {
	info := KnowledgeBaseInfo{}
	if v, ok := m["id"].(uint); ok {
		info.ID = v
	} else if v, ok := m["id"].(uint32); ok {
		info.ID = uint(v)
	} else if v, ok := m["id"].(int64); ok {
		info.ID = uint(v)
	} else if v, ok := m["id"].(float64); ok {
		info.ID = uint(v)
	}
	if v, ok := m["created_at"].(time.Time); ok {
		info.CreatedAt = v
	} else if v, ok := m["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.CreatedAt = t
		}
	}
	if v, ok := m["updated_at"].(time.Time); ok {
		info.UpdatedAt = v
	} else if v, ok := m["updated_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.UpdatedAt = t
		}
	}
	if v, ok := m["title"].(string); ok {
		info.Title = v
	}
	if v, ok := m["category"].(string); ok {
		info.Category = v
	}
	if v, ok := m["tags"].([]interface{}); ok {
		info.Tags = convertInterfaceSliceToStringSlice(v)
	}
	if v, ok := m["content"].(string); ok {
		info.Content = v
	}
	if v, ok := m["summary"].(string); ok {
		info.Summary = v
	}
	if v, ok := m["author"].(string); ok {
		info.Author = v
	}
	if v, ok := m["view_count"].(int); ok {
		info.ViewCount = v
	} else if v, ok := m["view_count"].(int64); ok {
		info.ViewCount = int(v)
	}
	if v, ok := m["like_count"].(int); ok {
		info.LikeCount = v
	} else if v, ok := m["like_count"].(int64); ok {
		info.LikeCount = int(v)
	}
	if v, ok := m["is_published"].(bool); ok {
		info.IsPublished = v
	}
	if v, ok := m["metadata"].(map[string]interface{}); ok {
		info.Metadata = make(map[string]string)
		for k, val := range v {
			if str, ok := val.(string); ok {
				info.Metadata[k] = str
			}
		}
	}
	return info
}

func convertInterfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if str, ok := v.(string); ok {
			result = append(result, str)
		}
	}
	return result
}
