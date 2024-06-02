package main

import (
	"bytes"
	"encoding/json"
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

//type clients struct {
//	socket  *websocket.Conn
//	receive chan []byte
//	room    *room
//}`

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
func (h *userHandler) ClientRedirectAfterPressingByAdmin(c *fiber.Ctx) error {
	var requestData struct {
		Success bool `json:"success"`
	}
	if err := c.BodyParser(&requestData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"success": false, "message": "Invalid request"})
	}

	if requestData.Success {
		h.mu.Lock()
		if h.clientConns["client"] != nil {
			h.clientConns["client"].WriteMessage(websocket.TextMessage, []byte("redirect"))
		}
		h.mu.Unlock()
		return c.JSON(fiber.Map{"success": true})
	}

	return c.JSON(fiber.Map{"success": false, "message": "Request not successful"})
}
func (h *userHandler) WaitingForRequests(c *fiber.Ctx) error {
	em := <-supportQueue
	log.Println("loh" + em)
	if em == "" {
		c.SendString("There is no requests for help")
	} else {
		c.Render("WaitingForRequests", fiber.Map{
			"Email": em,
		})
	}
	return nil
}

//	func (c *clients) readMsg() {
//		defer c.socket.Close()
//		for {
//			_, msg, err := c.socket.ReadMessage()
//			if err != nil {
//				log.Print(err)
//				return
//			}
//			c.room.forward <- msg
//		}
//	}
//
//	func (c *clients) writeMsg() {
//		defer c.socket.Close()
//		for msg := range c.receive {
//			err := c.socket.WriteMessage(ws.TextMessage, msg)
//			if err != nil {
//				log.Println(err)
//				return
//			}
//		}
//	}
//
// # Another way
//
//	func (h *userHandler) run() {
//		for {
//			select {
//			case message := <-h.broadcastCh:
//				h.broadcastMessage(message)
//			case <-h.stopCh:
//				return
//			}
//		}
//	}
//
//	func (h *userHandler) broadcastMessage(message []byte) {
//		h.mu.Lock()
//		defer h.mu.Unlock()
//
//		for _, conn := range h.clientConns {
//			if err := conn.WriteMessage(ws.TextMessage, message); err != nil {
//				log.Println("Error broadcasting to client:", err)
//			}
//		}
//
//		for _, conn := range h.adminConns {
//			if err := conn.WriteMessage(ws.TextMessage, message); err != nil {
//				log.Println("Error broadcasting to admin:", err)
//			}
//		}
//	}
//
//	func (h *userHandler) handleClientWebSocket(c *ws.Conn) {
//		defer func() {
//			h.mu.Lock()
//			delete(h.clientConns, "client")
//			h.mu.Unlock()
//			c.Close()
//		}()
//
//		h.mu.Lock()
//		h.clientConns["client"] = c
//		h.mu.Unlock()
//
//		for {
//			_, message, err := c.ReadMessage()
//			if err != nil {
//				break
//			}
//			log.Printf("Received from client: %s\n", message)
//			h.broadcastMessage(message)
//			log.Printf("Broadcasted to admins: %s\n", message)
//		}
//	}
//
//	func (h *userHandler) handleAdminWebSocket(c *ws.Conn) {
//		defer func() {
//			h.mu.Lock()
//			delete(h.adminConns, "admin")
//			h.mu.Unlock()
//			c.Close()
//		}()
//
//		h.mu.Lock()
//		h.adminConns["admin"] = c
//		h.mu.Unlock()
//
//		for {
//			_, message, err := c.ReadMessage()
//			if err != nil {
//				break
//			}
//			log.Printf("Received from admin: %s\n", message)
//			h.broadcastMessage(message)
//			log.Printf("Broadcasted to clients: %s\n", message)
//		}
//	}
var clients = make(map[*ws.Conn]bool)
var broadcast = make(chan []byte)

func (h *userHandler) handleConns(c *ws.Conn) {
	defer c.Close()

	clients[c] = true

	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			fmt.Println(err)
			delete(clients, c)
			return
		}
		log.Println("incoming msg to broadcast", string(msg))
		broadcast <- msg
	}
}
func handleMessages() {
	for {
		msg := <-broadcast
		log.Println("outcoming msg from broadcast", string(msg))
		for client := range clients {
			err := client.WriteMessage(ws.TextMessage, msg)
			if err != nil {
				fmt.Println(err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}
func (h *userHandler) ServeClientChat(c *fiber.Ctx) error {
	return c.Render("clientchat", nil)
}
func (h *userHandler) ServeAdminChat(c *fiber.Ctx) error {
	return c.Render("adminchat", nil)
}

//func (h *userHandler) CheckingForChat(c *fiber.Ctx) error {
//	chatID := uuid.NewString()
//	userEmail := storedEmail
//	chat := Chat{ID: chatID, UserID: userEmail, CreatedAt: time.Now()}
//	if h.DB.CheckExistChat(chat.UserID) {
//
//	} else {
//		result := h.DB.ChatCreate(chat.UserID, chat.CreatedAt)
//		if result != nil {
//			c.Status(500)
//			c.SendString("error in creating chat")
//			return result
//		}
//	}
//	return nil
//}

var ClientEmail string

func (h *userHandler) SendEmail(c *fiber.Ctx) error {
	var request struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(c.Body(), &request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"success": false, "message": "Invalid request body"})
	}
	if request.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"success": false, "message": "Email is required"})
	}
	supportQueue <- request.Email
	return nil
}

//func (h *userHandler) WaitingRoom(c *fiber.Ctx) error {
//	c.SendString("Wait till our support service accept you")
//	supportQueue <- ClientEmail
//	return nil
//}

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

type Transaction struct {
	TransactionID string `json:"transaction_id"`
	Subscription  string `json:"subscription"`
	Email         string `json:"email"`
}

func (h *userHandler) serverCheckout(c *fiber.Ctx) error {
	return c.Render("checkout", nil)
}
func (h *userHandler) CheckoutHandler(c *fiber.Ctx) error {
	var transaction Transaction
	if err := c.BodyParser(&transaction); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	transaction.TransactionID = uuid.New().String()
	fmt.Println("Transaction:", transaction)

	// Marshal transaction data to JSON
	transactionJSON, err := json.Marshal(transaction)
	if err != nil {
		fmt.Println("Error after marshal:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Error marshaling JSON")
	}

	// Send HTTP POST request to create-transaction endpoint
	resp, err := http.Post("http://127.0.0.1:8081/create-transaction", "application/json", bytes.NewBuffer(transactionJSON))
	if err != nil {
		fmt.Println("Error after POST request:", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Error sending HTTP request")
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error response status:", resp.Status)
		return c.Status(fiber.StatusInternalServerError).SendString("Unexpected status code from server")
	}

	// If everything is successful, send a response
	return c.SendString("Transaction successfully processed")
}
