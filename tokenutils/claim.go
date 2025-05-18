package tokenutils

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	SessionID uuid.UUID `json:"session_id"`
	UserGUID  uuid.UUID `json:"user_guid"`
	UserIP    string    `json:"user_ip"`
	jwt.RegisteredClaims
}

type ErrorResponse struct {
	Error string `json:"error"`
}
