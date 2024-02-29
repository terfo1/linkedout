package main

import (
	"bytes"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"time"
)

const (
	contextKeyUser = "user"
)

type (
	User struct {
		Email    string
		Name     string
		password string
	}
)
type RegisterRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (app *application) renderTemplate(w io.Writer, name string) error {
	ts, err := template.ParseFiles(name)
	if err != nil {
		app.logger.Error(err)
		return err
	}
	err = ts.Execute(w, nil)
	return err
}
func (app *application) homepage(c *fiber.Ctx) error {
	var buf bytes.Buffer
	if err := app.renderTemplate(&buf, "ui/pages/index.html"); err != nil {
		app.logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(fiber.StatusOK).Send(buf.Bytes())
}
func (h *AuthHandler) serveregisterpage(c *fiber.Ctx) error {
	var buf bytes.Buffer
	if err := h.App.renderTemplate(&buf, "ui/pages/register.html"); err != nil {
		h.App.logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(fiber.StatusOK).Send(buf.Bytes())
}
func (h *AuthHandler) register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	err := h.DB.RegisterUser(req.Email, req.Name, req.Password)
	if err == ErrUserAlreadyExists {
		h.App.logger.Info("User already exists")
		return c.Status(fiber.StatusConflict).SendString("user already exists")
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.SendStatus(fiber.StatusCreated)
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

var (
	errBadCredentials = errors.New("email or password is incorrect")
)

var jwtSecretKey = []byte("secretka")

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	regReq := LoginRequest{}
	if err := c.BodyParser(&regReq); err != nil {
		return fmt.Errorf("body parser: %w", err)
	}

	user, err := h.DB.GetUserByEmail(regReq.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.password), []byte(regReq.Password))
	if err != nil {
		// If the error is not nil, the comparison failed, indicating the password is incorrect
		return errBadCredentials
	}
	payload := jwt.MapClaims{
		"sub": user.Email,
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	t, err := token.SignedString(jwtSecretKey)
	if err != nil {
		logrus.WithError(err).Error("JWT token signing")
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(LoginResponse{AccessToken: t})
}

type ProfileResponse struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (h *userHandler) profile(c *fiber.Ctx) error {
	jwtPayload, ok := jwtPayloadFromRequest(c)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	}

	userEmail, ok := jwtPayload["sub"].(string)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized - user identifier not found in token")
	}

	userInfo, err := h.DB.GetUserByEmail(userEmail)
	if err != nil {
		h.App.logger.Error(err)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(ProfileResponse{
		Email: userInfo.Email,
		Name:  userInfo.Name,
	})
}
func jwtPayloadFromRequest(c *fiber.Ctx) (jwt.MapClaims, bool) {
	jwtToken, ok := c.Context().Value(contextKeyUser).(*jwt.Token)
	if !ok {
		logrus.WithFields(logrus.Fields{
			"jwt_token_context_value": c.Context().Value(contextKeyUser),
		}).Error("wrong type of JWT token in context")
		return nil, false
	}

	payload, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		logrus.WithFields(logrus.Fields{
			"jwt_token_claims": jwtToken.Claims,
		}).Error("wrong type of JWT token claims")
		return nil, false
	}

	return payload, true
}
