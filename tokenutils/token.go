package tokenutils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func GenerateRefreshToken() (string, string, error) {
	g := make([]byte, 32)

	_, err := rand.Read(g)
	if err != nil {
		return "", "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(g)

	hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 10)

	if err != nil {
		return "", "", err
	}

	return refreshToken, string(hashRefreshToken), nil

}

func GenerateAccessToken(sessionID, userGUID uuid.UUID, userIP string) (string, error) {
	claims := Claims{
		SessionID: sessionID,
		UserGUID:  userGUID,
		UserIP:    userIP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userGUID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return "", nil
	}

	return accessToken, nil
}

func ValidateRefreshToken(token, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))

	if err != nil {
		return err
	}

	return nil
}

func ValidateAccessToken(accessToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)

	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}
