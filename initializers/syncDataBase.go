package initializers

import "github.com/valtti-kortti/authorization_service_go/models"

func SyncDataBase() {
	err := DB.AutoMigrate(
		&models.RefreshToken{},
	)

	if err != nil {
		panic("Failed to migrate database: " + err.Error())
	}

}
