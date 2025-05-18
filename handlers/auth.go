package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/valtti-kortti/authorization_service_go/models"
	"github.com/valtti-kortti/authorization_service_go/tokenutils"
	"gorm.io/gorm"
)

// @Summary      Получение пары токенов
// @Description  Возвращает access и refresh токены по GUID пользователя
// @Tags         tokens
// @ID           get-tokens
// @Param        guid query string true "GUID пользователя"
// @Success      200 {object} tokenutils.TokenResponse
// @Failure      400 {object} tokenutils.ErrorResponse
// @Failure      500 {object} tokenutils.ErrorResponse
// @Router       /tokens [get]
func GetTokens(c *gin.Context, db *gorm.DB) {

	// Запрос на GUID
	guid := c.DefaultQuery("guid", "")

	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": " GUID is required",
		})
		return
	}

	// из типа string делаем тип uuid
	parsedUUID, err := uuid.Parse(guid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid UUID format",
		})
		return
	}

	// Получение Рефреш токена
	refreshToken, hashRefreshToken, err := tokenutils.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": " Failed to create Refresh Token",
		})
		return
	}

	// Создаем id сессии создания
	sessionID := uuid.New()

	// Генерируем access токен
	accessToken, err := tokenutils.GenerateAccessToken(sessionID, parsedUUID, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": " Failed to create Access Token",
		})
		return
	}

	// удаляем запись прошлого рефреш токена
	if err := db.Where("user_guid = ?", parsedUUID).Delete(&models.RefreshToken{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete previous refresh tokens",
		})
		return
	}

	refreshTokenRecord := models.RefreshToken{
		SessionID: sessionID,
		UserGUID:  parsedUUID,
		UserAgent: c.Request.UserAgent(),
		TokenHash: hashRefreshToken,
		IpAddress: c.ClientIP(),
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7),
	}

	result := db.Create(&refreshTokenRecord)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save refresh token",
		})
		return
	}

	// сохраняем в куки
	c.SetCookie("access_token", accessToken, 3600, "/", "", false, true)
	c.SetCookie("refresh_token", refreshToken, 3600*24*7, "/", "", false, true)

	c.JSON(http.StatusOK, tokenutils.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

}

// @Summary      Обновление пары токенов
// @Description  Обновляет access и refresh токены по куки пользователя
// @Tags         tokens
// @ID           refresh-tokens
// @Success      200 {object} tokenutils.TokenResponse
// @Failure      401 {object} tokenutils.ErrorResponse
// @Failure      500 {object} tokenutils.ErrorResponse
// @Router       /refresh [get]
func RefreshTokenPair(c *gin.Context, db *gorm.DB) {

	oldAccessToken, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Access token not found",
		})
		return
	}

	oldRefreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Refresh token not found",
		})
		return
	}

	//Получаем claims из access токена
	claims, err := tokenutils.ValidateAccessToken(oldAccessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid access token",
		})
		return
	}

	// Получаем из базы хеш токена
	var tokenModel models.RefreshToken
	if err := db.Where("session_id = ? AND user_guid= ?", claims.SessionID, claims.UserGUID).First(&tokenModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Проверка на валидность refresh токена
	err = tokenutils.ValidateRefreshToken(oldRefreshToken, tokenModel.TokenHash)
	if err != nil {
		_ = db.Delete(&tokenModel)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid refresh token",
		})
		return
	}

	//Проверка User-Agent
	if c.Request.UserAgent() != tokenModel.UserAgent {
		_ = db.Delete(&tokenModel)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User-Agent has changed",
		})
		return
	}

	//Проверка на то не истек ли срок годности
	if tokenModel.ExpiresAt.Before(time.Now()) {
		_ = db.Delete(&tokenModel)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Refresh token expired",
		})
		return
	}

	//Проверка на то были ли токены выпущены вместе
	if claims.SessionID != tokenModel.SessionID {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Refresh token and access token are not a pair",
		})
		return
	}

	//проверка на изменение IP
	if tokenModel.IpAddress != c.ClientIP() {
		go func() {
			webhookUrl := os.Getenv("WEBHOOK_URL")
			payload := map[string]string{
				"change_ip": c.ClientIP(),
				"user_guid": claims.UserGUID.String(),
			}

			jsonData, err := json.Marshal(payload)
			if err != nil {
				return
			}

			_, err = http.Post(webhookUrl, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				return
			}
		}()
	}

	// Получение  новый Рефреш токен
	refreshToken, hashRefreshToken, err := tokenutils.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": " Failed to create Refresh Token",
		})
		return
	}

	// Создаем id сессии создания
	sessionID := uuid.New()

	// Генерируем access токен
	accessToken, err := tokenutils.GenerateAccessToken(sessionID, claims.UserGUID, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": " Failed to create Access Token",
		})
		return
	}

	// удаляем запись прошлого рефреш токена
	_ = db.Delete(&tokenModel)

	refreshTokenRecord := models.RefreshToken{
		SessionID: sessionID,
		UserGUID:  claims.UserGUID,
		UserAgent: c.Request.UserAgent(),
		TokenHash: hashRefreshToken,
		IpAddress: c.ClientIP(),
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7),
	}

	result := db.Create(&refreshTokenRecord)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save refresh token",
		})
		return
	}

	// сохраняем в куки
	c.SetCookie("access_token", accessToken, 3600, "/", "", false, true)
	c.SetCookie("refresh_token", refreshToken, 3600*24*7, "/", "", false, true)

	c.JSON(http.StatusOK, tokenutils.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

}

// @Summary      Получение GUID пользователя
// @Description  Возвращает GUID аутентифицированного пользователя
// @Tags         user
// @ID           get-user-guid
// @Success      200 {object} map[string]string
// @Failure      401 {object} tokenutils.ErrorResponse
// @Router       /guid [get]
func GetUserGuid(c *gin.Context) {

	guid, exists := c.Get("guid")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"guid": guid,
	})
}

// @Summary      Выход пользователя
// @Description  Удаляет refresh токен пользователя и завершает сессию
// @Tags         user
// @ID           logout-user
// @Success      200 {object} map[string]string
// @Failure      401 {object} tokenutils.ErrorResponse
// @Router       /logout [get]
func LogoutUser(c *gin.Context, db *gorm.DB) {
	accessToken, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Access token not found",
		})
		return
	}

	//Получаем claims из access токена
	claims, err := tokenutils.ValidateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid access token",
		})
		return
	}

	var tokenModel models.RefreshToken
	if err := db.Where("session_id = ? AND user_guid= ?", claims.SessionID, claims.UserGUID).First(&tokenModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	_ = db.Delete(&tokenModel)

	c.JSON(http.StatusOK, gin.H{
		"message": "logout",
	})

}
