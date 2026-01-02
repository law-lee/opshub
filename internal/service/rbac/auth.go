package rbac

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ydcloud-dy/opshub/internal/biz/rbac"
)

type JwtClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type AuthService struct {
	secretKey   string
	roleUseCase *rbac.RoleUseCase
}

func NewAuthService(secretKey string, roleUseCase *rbac.RoleUseCase) *AuthService {
	return &AuthService{
		secretKey:   secretKey,
		roleUseCase: roleUseCase,
	}
}

func (s *AuthService) GenerateToken(userID uint, username string) (string, error) {
	claims := JwtClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

func (s *AuthService) ParseToken(tokenString string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
