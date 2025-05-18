package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/valtti-kortti/authorization_service_go/models"
	"github.com/valtti-kortti/authorization_service_go/tokenutils"
	"gorm.io/gorm"
)

func AuthMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Access token not found",
			})
			c.Abort()
			return
		}

		claims, err := tokenutils.ValidateAccessToken(accessToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid access token",
			})
			c.Abort()
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

		//Проверка на то не истек ли срок годности
		if tokenModel.ExpiresAt.Before(time.Now()) {
			_ = db.Delete(&tokenModel)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Refresh token expired",
			})
			return
		}

		c.Set("guid", claims.UserGUID.String())
		c.Next()
	}
}
