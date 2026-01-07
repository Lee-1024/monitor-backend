// ============================================
// 文件: api/user_handlers.go
// 用户管理相关的API处理器
// ============================================
package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// listUsers 获取用户列表（管理员）
func (s *APIServer) listUsers(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	pageNum, _ := strconv.Atoi(page)
	pageSizeNum, _ := strconv.Atoi(pageSize)

	users, total, err := s.storage.ListUsers(pageNum, pageSizeNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get users: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"users":     users,
			"total":     total,
			"page":      pageNum,
			"page_size": pageSizeNum,
		},
	})
}

// getUser 获取单个用户信息（管理员）
func (s *APIServer) getUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid user ID",
		})
		return
	}

	user, err := s.storage.GetUserByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    user,
	})
}

// createUser 创建用户（管理员）
func (s *APIServer) createUser(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 获取角色（默认为user）
	role := c.DefaultQuery("role", "user")
	if role != "admin" && role != "user" {
		role = "user"
	}

	// 加密密码
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to hash password",
		})
		return
	}

	// 创建用户
	user, err := s.storage.CreateUser(req.Username, req.Email, hashedPassword, role)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "User created successfully",
		Data:    user,
	})
}

// updateUser 更新用户信息（管理员）
func (s *APIServer) updateUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid user ID",
		})
		return
	}

	var req struct {
		Email  string `json:"email"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证角色
	if req.Role != "" && req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid role",
		})
		return
	}

	// 验证状态
	if req.Status != "" && req.Status != "active" && req.Status != "inactive" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid status",
		})
		return
	}

	// 更新用户
	if err := s.storage.UpdateUser(uint(id), req.Email, req.Role, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update user: " + err.Error(),
		})
		return
	}

	// 获取更新后的用户信息
	user, err := s.storage.GetUserByID(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get updated user",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "User updated successfully",
		Data:    user,
	})
}

// deleteUser 删除用户（管理员）
func (s *APIServer) deleteUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid user ID",
		})
		return
	}

	// 不能删除自己
	currentUserID, _ := c.Get("user_id")
	if currentUserID != nil && currentUserID.(uint) == uint(id) {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Cannot delete yourself",
		})
		return
	}

	if err := s.storage.DeleteUser(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete user: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "User deleted successfully",
	})
}

// resetUserPassword 重置用户密码（管理员）
func (s *APIServer) resetUserPassword(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid user ID",
		})
		return
	}

	var req struct {
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 加密新密码
	hashedPassword, err := HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to hash password",
		})
		return
	}

	// 更新密码
	if err := s.storage.UpdateUserPassword(uint(id), hashedPassword); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to reset password: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Password reset successfully",
	})
}

