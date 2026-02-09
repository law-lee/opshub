// Copyright (c) 2026 DYCloud J.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package identity

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ydcloud-dy/opshub/internal/biz/identity"
	"github.com/ydcloud-dy/opshub/pkg/response"
)

// OAuth2ServerService OAuth2服务端服务
type OAuth2ServerService struct {
	useCase *identity.OAuth2ServerUseCase
}

// NewOAuth2ServerService 创建OAuth2服务端服务
func NewOAuth2ServerService(useCase *identity.OAuth2ServerUseCase) *OAuth2ServerService {
	return &OAuth2ServerService{useCase: useCase}
}

// Authorize OAuth2授权端点
func (s *OAuth2ServerService) Authorize(c *gin.Context) {
	req := &identity.AuthorizeRequest{
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		ResponseType:        c.Query("response_type"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	// 验证请求
	app, err := s.useCase.ValidateAuthorizeRequest(c.Request.Context(), req)
	if err != nil {
		s.redirectWithError(c, req.RedirectURI, req.State, "invalid_request", err.Error())
		return
	}

	// 检查用户是否已登录
	userID, exists := c.Get("userID")
	if !exists {
		// 重定向到登录页，登录后返回
		loginURL := "/login?redirect=" + url.QueryEscape(c.Request.URL.String())
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// 检查用户是否有权限访问该应用
	// 这里简化处理，实际应该检查权限

	// 如果需要显示授权同意页面
	if c.Query("consent") != "true" {
		// 返回授权同意页面数据
		c.JSON(http.StatusOK, gin.H{
			"needConsent": true,
			"app": gin.H{
				"id":          app.ID,
				"name":        app.Name,
				"icon":        app.Icon,
				"description": app.Description,
			},
			"scopes":   identity.ParseScope(req.Scope),
			"clientId": req.ClientID,
			"state":    req.State,
		})
		return
	}

	// 创建授权码
	authResp, err := s.useCase.CreateAuthorizationCode(c.Request.Context(), req, userID.(uint))
	if err != nil {
		s.redirectWithError(c, req.RedirectURI, req.State, "server_error", err.Error())
		return
	}

	// 重定向回客户端
	redirectURL := s.buildRedirectURL(req.RedirectURI, authResp.Code, authResp.State)
	c.Redirect(http.StatusFound, redirectURL)
}

// Token OAuth2令牌端点
func (s *OAuth2ServerService) Token(c *gin.Context) {
	var req identity.TokenRequest

	// 支持form和json两种格式
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			s.tokenError(c, "invalid_request", err.Error())
			return
		}
	} else {
		req.GrantType = c.PostForm("grant_type")
		req.Code = c.PostForm("code")
		req.RedirectURI = c.PostForm("redirect_uri")
		req.ClientID = c.PostForm("client_id")
		req.ClientSecret = c.PostForm("client_secret")
		req.CodeVerifier = c.PostForm("code_verifier")
		req.RefreshToken = c.PostForm("refresh_token")
	}

	// 支持Basic Auth传递client credentials
	if req.ClientID == "" {
		clientID, clientSecret, ok := c.Request.BasicAuth()
		if ok {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}

	// 交换令牌
	tokenResp, err := s.useCase.ExchangeToken(c.Request.Context(), &req)
	if err != nil {
		s.tokenError(c, "invalid_grant", err.Error())
		return
	}

	c.JSON(http.StatusOK, tokenResp)
}

// UserInfo OAuth2用户信息端点
func (s *OAuth2ServerService) UserInfo(c *gin.Context) {
	// 从Authorization header获取access token
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		response.ErrorCode(c, http.StatusUnauthorized, "missing authorization header")
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		response.ErrorCode(c, http.StatusUnauthorized, "invalid authorization header")
		return
	}

	accessToken := parts[1]

	userInfo, err := s.useCase.GetUserInfo(c.Request.Context(), accessToken)
	if err != nil {
		response.ErrorCode(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// Discovery OIDC发现端点
func (s *OAuth2ServerService) Discovery(c *gin.Context) {
	discovery := s.useCase.GetOIDCDiscovery()
	c.JSON(http.StatusOK, discovery)
}

// JWKS JWKS端点（简化版，返回空）
func (s *OAuth2ServerService) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"keys": []interface{}{},
	})
}

// Revoke 令牌撤销端点
func (s *OAuth2ServerService) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		response.ErrorCode(c, http.StatusBadRequest, "missing token")
		return
	}

	if err := s.useCase.RevokeToken(c.Request.Context(), token); err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.Status(http.StatusOK)
}

// Introspect 令牌内省端点
func (s *OAuth2ServerService) Introspect(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	tokenRecord, err := s.useCase.ValidateAccessToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"client_id": tokenRecord.ClientID,
		"sub":       tokenRecord.UserID,
		"scope":     tokenRecord.Scope,
		"exp":       tokenRecord.ExpiresAt.Unix(),
		"iat":       tokenRecord.CreatedAt.Unix(),
	})
}

// 辅助函数

func (s *OAuth2ServerService) redirectWithError(c *gin.Context, redirectURI, state, errorCode, errorDesc string) {
	if redirectURI == "" {
		response.ErrorCode(c, http.StatusBadRequest, errorCode+": "+errorDesc)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		response.ErrorCode(c, http.StatusBadRequest, "invalid redirect_uri")
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, u.String())
}

func (s *OAuth2ServerService) tokenError(c *gin.Context, errorCode, errorDesc string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             errorCode,
		"error_description": errorDesc,
	})
}

func (s *OAuth2ServerService) buildRedirectURL(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return u.String()
}
