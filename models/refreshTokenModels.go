package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model

	SessionID uuid.UUID `gorm:"type:uuid" json:"session_id"`
	UserGUID  uuid.UUID `gorm:"type:uuid" json:"user_guid"`
	UserAgent string    `gorm:"type:text" json:"user_agent"`
	TokenHash string    `gorm:"type:text" json:"token_hash"`
	IpAddress string    `gorm:"type:varchar(45)" json:"ip_address"`
	ExpiresAt time.Time `json:"expires_at"`
}
