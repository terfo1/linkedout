package main

import (
	"bytes"
	"fmt"
	ws "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
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

var storedEmail string

type Message struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	ChatID    string    `json:"chat_id"`
	SenderID  string    `json:"sender_id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

type Chat struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}
var supportQueue = make(chan string, 10)

func sendConfirmationEmail(to, token string) error {
	from := "alisher.temirhan@gmail.com"
	password := "lfcv mmen wonp ggrx"

	toEmail := []string{to}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	message := []byte("To: " + to + "\r\n" +
		"Confirm your email address\r\n" +
		"\r\n" +
		"Here is your confirmation token:\r\n" +
		token + "\r\n")

	auth := smtp.PlainAuth("", from, password, smtpHost)

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
		c.SendString("Password is incorrect")
		return errBadCredentials

	}
	payload := jwt.MapClaims{
		"sub": user.Email,
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	t, err := token.SignedString(jwtSecretKey)
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
	storeEmail(user.Email)
	return c.Redirect("/profile")
}
func storeEmail(email string) error {
	storedEmail = email
	return nil
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
	sort := c.Query("sort", "added_date DESC")
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

//	func LoadJobsFromFile(filePath string) ([]Job, error) {
//		file, err := os.Open(filePath)
//		if err != nil {
//			return nil, err
//		}
//		defer file.Close()
//
//		var jsonData []byte
//		scanner := bufio.NewScanner(file)
//		for scanner.Scan() {
//			line := scanner.Text()
//			// Remove carriage returns from each line
//			line = strings.ReplaceAll(line, "\r", "")
//			jsonData = append(jsonData, line...)
//		}
//
//		var jobs []Job
//		err = json.Unmarshal(jsonData, &jobs)
//		if err != nil {
//			return nil, err
//		}
//
//		return jobs, nil
//	}
func (h *userHandler) Admin(c *fiber.Ctx) error {
	if h.DB.CheckForAdmin(storedEmail) == false {
		c.SendStatus(401)
	}
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	var jobs []Job
	for i := range form.Value["name[]"] {
		job := Job{
			Name:        form.Value["name[]"][i],
			Company:     form.Value["company[]"][i],
			Description: form.Value["description[]"][i],
			Email:       form.Value["email[]"][i],
		}
		jobs = append(jobs, job)
	}
	//jobs, err := LoadJobsFromFile("cmd/jobs.json")
	//if err != nil {
	//	log.Fatalf("Failed to load jobs from file: %v", err)
	//}
	numJobs := len(jobs)
	errCh := make(chan error, numJobs)
	workerCount := 1
	jobCh := make(chan Job, numJobs)
	defer close(jobCh)
	start := time.Now()
	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobCh {
				addedDate := time.Now()
				err := h.DB.InsertJob(job.Name, job.Company, job.Description, addedDate, job.Email)
				errCh <- err
			}
		}()
	}
	for _, job := range jobs {
		jobCh <- job
	}
	end := time.Since(start)
	for i := 0; i < numJobs; i++ {
		if err := <-errCh; err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
	}
	log.Print("time with 2 goroutines:", end)
	return c.Redirect("/admin")
}
func (h *userHandler) ServeAdmin(c *fiber.Ctx) error {
	users, err := h.DB.GetUsersEmail()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to fetch users")
	}
	return c.Render("admin", fiber.Map{
		"Users": users,
	})
}
func (h *userHandler) sendAdminEmail(c *fiber.Ctx) error {
	from := "alisher.temirhan@gmail.com"
	password := "lfcv mmen wonp ggrx"
	toEmail := c.FormValue("userEmail")
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	subject := "Message"
	body := c.FormValue("msg")
	message := []byte(
		"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
			"From: " + from + "\r\n" +
			"To: " + toEmail + "\r\n" +
			"Subject: " + subject + "\r\n\r\n" +
			body,
	)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	toEmails := []string{toEmail}
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, toEmails, message)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Email Sent Successfully!")
	return nil
}

func (h *userHandler) WaitingForRequests(c *fiber.Ctx) error {
	log.Println(storedEmail)
	if supportQueue == nil {
		c.SendString("There is no requests for help")
	} else {
		c.Render("WaitingForRequests", fiber.Map{
			"Email": storedEmail,
		})
	}
	return nil
}
func (h *userHandler) ServeAdminChat(c *fiber.Ctx) error {
	return c.Render("adminchat", nil)
}
func (h *userHandler) CreateChat(c *fiber.Ctx) error {
	chatID := uuid.NewString()
	userEmail := storedEmail
	chat := Chat{ID: chatID, UserID: userEmail, CreatedAt: time.Now()}
	result := h.DB.ChatCreate(chat.UserID, chat.CreatedAt)
	if result != nil {
		c.Status(500)
		c.SendString("error in creating chat")
		return result
	}
	return nil
}
func (h *userHandler) WaitingRoom(c *fiber.Ctx) error {
	c.SendString("Wait till our support service accept you")
	supportQueue <- storedEmail
	return nil
}

// func (h *userHandler) SendMessage(c *fiber.Ctx) error {
//
// }
func (h *userHandler) MessageFromAdmin(c *ws.Conn) {
	defer func() {
		if err := c.Close(); err != nil {
			log.Println("WebSocket Close Error:", err)
		}
	}()
	for {
		messageType, message, err := c.ReadMessage()
		if err != nil {
			log.Println("WebSocket Read Error:", err)
			break
		}
		log.Printf("Received: %s\n", message)
		if err := c.WriteMessage(messageType, message); err != nil {
			log.Println("WebSocket Write Error:", err)
			break
		}
	}
}
