package main

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/valtti-kortti/authorization_service_go/docs"
	"github.com/valtti-kortti/authorization_service_go/handlers"
	"github.com/valtti-kortti/authorization_service_go/initializers"
	"github.com/valtti-kortti/authorization_service_go/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDataBase()
}

// @title Authorization service

// @host localhost:3000
// @BasePath /

func main() {
	r := gin.Default()
	db := initializers.DB // Получаем соединение с БД

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/tokens", func(c *gin.Context) {
		handlers.GetTokens(c, db)
	})

	r.GET("/refresh", func(c *gin.Context) {
		handlers.RefreshTokenPair(c, db)
	})

	r.Use(middleware.AuthMiddleware(db))
	{
		r.GET("/guid", func(c *gin.Context) {
			handlers.GetUserGuid(c)
		})

		r.GET("/logout", func(c *gin.Context) {
			handlers.LogoutUser(c, db)
		})
	}

	r.Run()

}
