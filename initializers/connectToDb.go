package initializers

import (
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectToDb() {
	var err error

	dns := os.Getenv("DB")

	DB, err = gorm.Open(postgres.Open(dns), &gorm.Config{})

	if err != nil {
		panic("Fail to connect to DB")
	}
}
