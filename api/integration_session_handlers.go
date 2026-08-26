package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const corootSessionCookie = "monitor_coroot_session"

type corootSessionClaims struct {
	UserID uint   `json:"user_id"`
	Scope  string `json:"scope"`
	jwt.RegisteredClaims
}

func (s *APIServer) createCorootSession(c *gin.Context) {
	if s.corootAdapter == nil {
		c.JSON(http.StatusServiceUnavailable, Response{Code: http.StatusServiceUnavailable, Message: "Coroot 未启用"})
		return
	}
	userID, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "未登录"})
		return
	}
	id, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "用户会话无效"})
		return
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, corootSessionClaims{UserID: id, Scope: "coroot:readonly", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)), IssuedAt: jwt.NewNumericDate(now), Issuer: "monitor-backend"}})
	signed, err := token.SignedString(JWTSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "创建 Coroot 会话失败"})
		return
	}
	c.SetCookie(corootSessionCookie, signed, 600, "/coroot", "", false, true)
	c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: map[string]interface{}{"expires_in": 600}})
}

func (s *APIServer) checkCorootSession(c *gin.Context) {
	tokenString, err := c.Cookie(corootSessionCookie)
	if err != nil || tokenString == "" {
		c.Status(http.StatusUnauthorized)
		return
	}
	var claims corootSessionClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) { return JWTSecretKey, nil })
	if err != nil || !token.Valid || claims.Scope != "coroot:readonly" {
		c.Status(http.StatusUnauthorized)
		return
	}
	c.Header("X-User-ID", fmt.Sprintf("%d", claims.UserID))
	c.Status(http.StatusNoContent)
}

func (s *APIServer) clearCorootSession(c *gin.Context) {
	c.SetCookie(corootSessionCookie, "", -1, "/coroot", "", false, true)
	c.Status(http.StatusNoContent)
}
