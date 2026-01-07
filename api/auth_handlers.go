// ============================================
// 文件: api/auth_handlers.go
// 用户认证相关的API处理器
// ============================================
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// register 用户注册
func (s *APIServer) register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
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

	// 创建用户（默认角色为user）
	user, err := s.storage.CreateUser(req.Username, req.Email, hashedPassword, "user")
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	// 生成Token
	token, err := GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate token",
		})
		return
	}

	refreshToken, err := GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "User registered successfully",
		Data: AuthResponse{
			Token:        token,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(TokenExpireDuration.Seconds()),
			User:         *user,
		},
	})
}

// login 用户登录
func (s *APIServer) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 获取用户信息（包含密码哈希）
	user, passwordHash, err := s.storage.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "Invalid username or password",
		})
		return
	}

	// 检查用户状态
	if user.Status != "active" {
		c.JSON(http.StatusForbidden, Response{
			Code:    403,
			Message: "User account is inactive",
		})
		return
	}

	// 验证密码
	if !CheckPassword(passwordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "Invalid username or password",
		})
		return
	}

	// 更新最后登录时间
	s.storage.UpdateUserLastLogin(user.ID)

	// 生成Token
	token, err := GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate token",
		})
		return
	}

	refreshToken, err := GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Login successful",
		Data: AuthResponse{
			Token:        token,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(TokenExpireDuration.Seconds()),
			User:         *user,
		},
	})
}

// refreshToken 刷新Token
func (s *APIServer) refreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 解析刷新Token
	userID, err := ParseRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "Invalid refresh token",
		})
		return
	}

	// 获取用户信息
	user, err := s.storage.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "User not found",
		})
		return
	}

	// 检查用户状态
	if user.Status != "active" {
		c.JSON(http.StatusForbidden, Response{
			Code:    403,
			Message: "User account is inactive",
		})
		return
	}

	// 生成新Token
	token, err := GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate token",
		})
		return
	}

	newRefreshToken, err := GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Token refreshed successfully",
		Data: AuthResponse{
			Token:        token,
			RefreshToken: newRefreshToken,
			ExpiresIn:    int64(TokenExpireDuration.Seconds()),
			User:         *user,
		},
	})
}

// getCurrentUser 获取当前用户信息
func (s *APIServer) getCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "Unauthorized",
		})
		return
	}

	user, err := s.storage.GetUserByID(userID.(uint))
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

// changePassword 修改密码
func (s *APIServer) changePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "Unauthorized",
		})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证旧密码
	_, passwordHash, err := s.storage.GetUserByUsername(c.GetString("username"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{
			Code:    401,
			Message: "User not found",
		})
		return
	}

	if !CheckPassword(passwordHash, req.OldPassword) {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Old password is incorrect",
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
	if err := s.storage.UpdateUserPassword(userID.(uint), hashedPassword); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update password",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Password changed successfully",
	})
}

