package main

import (
	"database/sql"
	"fmt"
	"gopkg.in/gomail.v2"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jung-kurt/gofpdf"
	_ "github.com/lib/pq"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "postgresql://postgres:terfo2005@localhost/linkedout?sslmode=disable")
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
}

type Transaction struct {
	TransactionID string `json:"transaction_id"`
	Subscription  string `json:"subscription"`
	Status        string `json:"status"`
	Email         string `json:"email"`
}

func main() {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	})
	app.Post("/create-transaction", createTransactionHandler)
	app.Get("/payment", paymentFormHandler)
	app.Post("/payment", paymentHandler)

	log.Fatal(app.Listen(":8081"))
}

func paymentFormHandler(c *fiber.Ctx) error {
	return c.Render("C:\\Users\\LEGION\\Desktop\\aitu\\go\\LinkedOut\\service\\payment.tmpl", nil)
}

func createTransactionHandler(c *fiber.Ctx) error {
	var transaction Transaction
	if err := c.BodyParser(&transaction); err != nil {
		c.SendString("error in parsing")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	transaction.Status = "awaiting payment"
	if err := saveTransaction(transaction); err != nil {
		c.SendString("error in saveing transaction")
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	return c.JSON(transaction)
}

func saveTransaction(transaction Transaction) error {
	query := `INSERT INTO transactions (transaction_id, status, email) VALUES ($1, $2, $3)`
	_, err := db.Exec(query, transaction.TransactionID, transaction.Status, transaction.Email)
	return err
}

func paymentHandler(c *fiber.Ctx) error {
	var requestBody struct {
		TransactionID string `json:"transaction_id"`
	}

	if err := c.BodyParser(&requestBody); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	if requestBody.TransactionID == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Transaction ID is required")
	}

	if err := updateTransactionStatus(requestBody.TransactionID, "paid"); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	transaction, err := getTransaction(requestBody.TransactionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	fileName, err := generateReceipt(transaction)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	if err := sendReceipt(transaction.Email, fileName); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	finalizeTransaction(requestBody.TransactionID)
	return c.SendString("Payment successful and receipt sent!")
}

func updateTransactionStatus(transactionID, status string) error {
	query := `UPDATE transactions SET status=$1 WHERE transaction_id=$2`
	_, err := db.Exec(query, status, transactionID)
	return err
}

func getTransaction(transactionID string) (Transaction, error) {
	var transaction Transaction
	query := `SELECT transaction_id, email, status FROM transactions WHERE transaction_id=$1`
	err := db.QueryRow(query, transactionID).Scan(&transaction.TransactionID, &transaction.Email, &transaction.Status)
	if err != nil {
		return transaction, err
	}
	return transaction, nil
}

func generateReceipt(transaction Transaction) (string, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "LinkedOut")
	pdf.Ln(12)
	pdf.Cell(40, 10, "Transaction ID: "+string(transaction.TransactionID))
	pdf.Ln(12)
	pdf.Cell(40, 10, "Date: "+time.Now().Format("02-01-2006 15:04"))
	pdf.Ln(12)
	fileName := "receipt_" + string(transaction.TransactionID) + ".pdf"
	err := pdf.OutputFileAndClose(fileName)
	return fileName, err
}

func sendReceipt(email, fileName string) error {
	from := "alisher.temirhan@gmail.com"
	password := "lfcv mmen wonp ggrx"
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Your Fiscal Receipt")
	m.SetBody("text/plain", "Please find attached your fiscal receipt.")
	m.Attach(fileName)

	d := gomail.NewDialer("smtp.gmail.com", 587, from, password)

	return d.DialAndSend(m)
}

func finalizeTransaction(transactionID string) {
	updateTransactionStatus(transactionID, "completed")
}
