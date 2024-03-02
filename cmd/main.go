package main

import (
	"flag"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"os"
)

type application struct {
	fiberApp *fiber.App
	logger   *logrus.Logger
}
type AuthHandler struct {
	DB  *DB
	App *application
}
type userHandler struct {
	DB  *DB
	App *application
}

func main() {

	logger := logrus.New()
	file, err := os.OpenFile("log.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	logger.SetOutput(file)
	logger.SetFormatter(&logrus.JSONFormatter{})

	if err := godotenv.Load(); err != nil {
		logger.Fatal("Error loading .env file")
	}
	fiberapp := fiber.New(
		fiber.Config{Views: html.New("./ui/pages", ".tmpl")})
	app := &application{
		fiberApp: fiberapp,
		logger:   logger,
	}
	dbURL := os.Getenv("DATABASE_URL")
	db, err := NewDatabase(dbURL)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	app.fiberApp.Static("/static/", "./ui/static/")
	userHandler := userHandler{DB: db, App: app}
	authHandler := AuthHandler{DB: db}
	publicGroup := app.fiberApp.Group("")
	app.fiberApp.Get("/", app.homepage)
	publicGroup.Get("/register", authHandler.serveregisterpage)
	publicGroup.Post("/register", authHandler.register)
	publicGroup.Get("/login", authHandler.serveLogin)
	publicGroup.Post("/login", authHandler.Login)
	publicGroup.Get("/confirm", authHandler.serveconfirm)
	publicGroup.Post("/confirm", authHandler.ConfirmEmail)
	authorizedGroup := app.fiberApp.Group("/")
	app.fiberApp.Use(func(c *fiber.Ctx) error {
		jwtToken := c.Cookies("jwt")
		if jwtToken != "" {
			c.Request().Header.Add("Authorization", "Bearer "+jwtToken)
		}
		return c.Next()
	})
	authorizedGroup.Use(jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key: jwtSecretKey,
		},
		ContextKey: contextKeyUser,
	}))
	authorizedGroup.Get("/profile", userHandler.profile)
	authorizedGroup.Get("/jobs", userHandler.Jobs)
	address := flag.String("addr", ":4000", "HTTP server address")
	flag.Parse()
	logger.Fatal(app.fiberApp.Listen(*address))
}
