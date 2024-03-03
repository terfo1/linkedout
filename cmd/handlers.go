package main

import (
	"bytes"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"net/smtp"
	"strconv"
	"time"
)

const (
	contextKeyUser = "user"
)

type (
	User struct {
		Email                       string
		Name                        string
		Password                    string
		ConfirmationToken           string
		ConfirmationTokenExpiration time.Time
		email_confirmed             bool
		is_admin                    bool
	}
	Job struct {
		ID          int
		Name        string
		Company     string
		Description string
		AddedDate   time.Time
		Email       string
	}
)
type RegisterRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func sendConfirmationEmail(to, token string) error {
	from := "alisher.temirhan@gmail.com"
	password := "lfcv mmen wonp ggrx"

	// Receiver email address.
	toEmail := []string{to}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Message.
	message := []byte("To: " + to + "\r\n" +
		"Confirm your email address\r\n" +
		"\r\n" +
		"Here is your confirmation token:\r\n" +
		token + "\r\n")

	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Sending email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, toEmail, message)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Email Sent Successfully!")
	return nil
}
func (app *application) renderTemplate(w io.Writer, name string, data interface{}) error {
	ts, err := template.ParseFiles(name)
	if err != nil {
		app.logger.Error(err)
		return err
	}
	err = ts.Execute(w, nil)
	return err
}
func (app *application) homepage(c *fiber.Ctx) error {
	return c.Render("homepage", nil)
}
func (h *AuthHandler) serveregisterpage(c *fiber.Ctx) error {
	return c.Render("register", nil)
}
func (h *AuthHandler) register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	confirmationToken := uuid.NewString()
	tokenExpiration := time.Now().Add(24 * time.Hour)
	err := h.DB.RegisterUser(req.Email, req.Name, req.Password, confirmationToken, tokenExpiration)
	if err == ErrUserAlreadyExists {
		h.App.logger.Info("User already exists")
		return c.Status(fiber.StatusConflict).SendString("user already exists")
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	sendConfirmationEmail(req.Email, confirmationToken)
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Redirect("/confirm", 301)
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	RedirectURL string `json:"redirectUrl"`
}

var (
	errBadCredentials = errors.New("email or password is incorrect")
)

var jwtSecretKey = []byte("secretka")

func (h *AuthHandler) serveLogin(c *fiber.Ctx) error {
	return c.Render("login", nil)
}
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	regReq := LoginRequest{}
	if err := c.BodyParser(&regReq); err != nil {
		return fmt.Errorf("body parser: %w", err)
	}
	fmt.Println(regReq)
	user, err := h.DB.GetUserByEmail(regReq.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("getuserbyemail fail")
	}
	confirmedemail, err := h.DB.ConfirmedEmail(user.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("confirm failed")
	}
	if !confirmedemail {
		c.SendString("Email is not confirmed")
		return c.Redirect("/login")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(regReq.Password))
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
	fmt.Println("ss", t)
	if err != nil {
		h.App.logger.Error(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    t,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
	})
	if h.DB.CheckForAdmin(user.Email) {
		c.Redirect("/admin")
	}
	return c.Redirect("/profile")
}

type ProfileResponse struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (h *userHandler) profile(c *fiber.Ctx) error {
	jwtPayload, ok, err := jwtPayloadFromRequest(c)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).SendString("UnAuthorizeed")
	}
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
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
	return c.Render("profile", fiber.Map{
		"Email": userInfo.Email,
		"Name":  userInfo.Name,
	})
}
func jwtPayloadFromRequest(c *fiber.Ctx) (jwt.MapClaims, bool, error) {
	jwtToken, ok := c.Locals(contextKeyUser).(*jwt.Token)
	if !ok {
		return nil, false, errors.New("JWT token not found in context")
	}

	if !jwtToken.Valid {
		return nil, false, errors.New("invalid or expired JWT token")
	}

	payload, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false, errors.New("error extracting claims from JWT token")
	}

	return payload, true, nil
}

func (h *AuthHandler) serveconfirm(c *fiber.Ctx) error {
	var buf bytes.Buffer
	if err := h.App.renderTemplate(&buf, "ui/pages/confirm.html", nil); err != nil {
		h.App.logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(fiber.StatusOK).Send(buf.Bytes())
}
func (h *AuthHandler) ConfirmEmail(c *fiber.Ctx) error {
	token := c.FormValue("token")
	if token == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing token")
	}
	user, err := h.DB.GetUserByConfirmToken(token)
	if err != nil {
		h.App.logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).SendString("Error processing your request")
	}
	fmt.Println("Here is email" + user.Email)
	err = h.DB.UpdateConfirm(token)
	if err != nil {
		h.App.logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to confirm email")
	}
	return c.Redirect("/login")
}
func (h *userHandler) Jobs(c *fiber.Ctx) error {
	payload, ok, err := jwtPayloadFromRequest(c)
	if !ok || err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	}
	userEmail, ok := payload["sub"].(string)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized - user identifier not found in token")
	}
	nameFilter := c.Query("name")
	companyFilter := c.Query("company")
	sort := c.Query("sort", "added_date DESC") // Значение по умолчанию
	page := c.Query("page", "1")
	pageSize := c.Query("pageSize", "3")
	pageNum, err := strconv.Atoi(page)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid page number"})
	}

	pageSizeNum, err := strconv.Atoi(pageSize)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid page size"})
	}
	offset := (pageNum - 1) * pageSizeNum
	totalCount, err := h.DB.CountJobs(nameFilter, companyFilter, userEmail)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to count jobs"})
	}

	totalPages := (totalCount + pageSizeNum - 1) / pageSizeNum
	pages := make([]int, totalPages)
	for i := range pages {
		pages[i] = i + 1
	}
	jobs, err := h.DB.QueryJobs(nameFilter, companyFilter, sort, pageSizeNum, offset, userEmail)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch jobs"})
	}

	data := fiber.Map{
		"Title":         "Job Listings",
		"Jobs":          jobs,
		"Pages":         pages,
		"CurrentPage":   pageNum,
		"NameFilter":    nameFilter,
		"CompanyFilter": companyFilter,
		"Sort":          sort,
	}

	if err := c.Render("jobs", data); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
	}
	return nil
}
func (h *userHandler) Admin(c *fiber.Ctx) error {
	req := Job{}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	added_date := time.Now()
	err := h.DB.InsertJob(req.Name, req.Company, req.Description, added_date, req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	return c.Redirect("/admin")
}
func (h *userHandler) ServeAdmin(c *fiber.Ctx) error {
	return c.Render("admin", nil)
}
