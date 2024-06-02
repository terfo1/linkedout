package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type DB struct {
	Pool *pgxpool.Pool
}

var ErrUserAlreadyExists = errors.New("user already exists")

func NewDatabase(url string) (*DB, error) {
	dbPool, err := pgxpool.Connect(context.Background(), url)
	if err != nil {
		return nil, err
	}

	return &DB{Pool: dbPool}, nil
}

func (db *DB) RegisterUser(email, name, password string, confirmationToken string, tokenExpiration time.Time) error {
	ctx := context.Background()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	var exists bool
	err = db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrUserAlreadyExists
	}
	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, name, password,confirmation_token,token_expiration) VALUES ($1, $2, $3, $4, $5)", email, name, string(hashedPassword), confirmationToken, tokenExpiration)
	return err
}
func (db *DB) GetUserByEmail(email string) (*User, error) {
	ctx := context.Background()
	user := &User{}

	err := db.Pool.QueryRow(ctx, "SELECT email, name, password FROM users WHERE email=$1", email).Scan(&user.Email, &user.Name, &user.Password)
	if err != nil {
		fmt.Printf("Error in GetUserByEmail: %v\n", err)
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("no user found with the email %s: %w", email, err)
		}
		return nil, fmt.Errorf("error querying user by email %s: %w", email, err)
	}
	return user, nil
}

func (db *DB) GetUserByConfirmToken(token string) (*User, error) {
	ctx := context.Background()
	user := &User{}
	err := db.Pool.QueryRow(ctx, "SELECT confirmation_token,token_expiration FROM users WHERE confirmation_token = $1", token).Scan(&user.ConfirmationToken, &user.ConfirmationTokenExpiration)

	if err != nil {
		logrus.Info("Didn't get token")
		return nil, err
	}
	if user.ConfirmationTokenExpiration.Before(time.Now()) {
		return nil, errors.New("confirmation token is expired")
	}

	return user, nil
}
func (db *DB) ConfirmedEmail(email string) (bool, error) {
	ctx := context.Background()
	var emailConfirmed bool
	err := db.Pool.QueryRow(ctx, "SELECT email_confirmed FROM users WHERE email=$1", email).Scan(&emailConfirmed)
	if err != nil {
		logrus.WithError(err).Info("Error checking email confirmation")
		return false, err
	}
	return emailConfirmed, nil
}
func (db *DB) UpdateConfirm(token string) error {
	ctx := context.Background()
	db.Pool.QueryRow(ctx, "UPDATE users SET email_confirmed = TRUE WHERE confirmation_token = $1", token)
	return nil
}
func (db *DB) QueryJobs(nameFilter, companyFilter, sort string, pageSizeNum, offset int, email string) ([]Job, error) {
	ctx := context.Background()
	query := `SELECT id, name, company, description, added_date FROM jobs WHERE 1=1`

	args := []interface{}{}
	if nameFilter != "" {
		query += fmt.Sprintf(" AND name ILIKE $%d", len(args)+1)
		args = append(args, "%"+nameFilter+"%")
	}
	if companyFilter != "" {
		query += fmt.Sprintf(" AND company ILIKE $%d", len(args)+1)
		args = append(args, "%"+companyFilter+"%")
	}

	if sort != "" {
		query += fmt.Sprintf(" ORDER BY %s", sort)
	} else {
		query += " ORDER BY added_date DESC"
	}

	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, pageSizeNum, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jobs := make([]Job, 0)
	for rows.Next() {
		var job Job
		if err := rows.Scan(&job.ID, &job.Name, &job.Company, &job.Description, &job.AddedDate); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}
func (db *DB) CountJobs(nameFilter, companyFilter, email string) (int, error) {
	ctx := context.Background()
	query := "SELECT COUNT(*) FROM jobs WHERE 1=1"

	args := []interface{}{}
	if nameFilter != "" {
		query += fmt.Sprintf(" AND name ILIKE $%d", len(args)+1)
		args = append(args, "%"+nameFilter+"%")
	}
	if companyFilter != "" {
		query += fmt.Sprintf(" AND company ILIKE $%d", len(args)+1)
		args = append(args, "%"+companyFilter+"%")
	}

	var count int
	err := db.Pool.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
func (db *DB) CheckForAdmin(email string) bool {
	ctx := context.Background()
	var isAdmin bool
	err := db.Pool.QueryRow(ctx, "SELECT is_admin FROM users WHERE email=$1", email).Scan(&isAdmin)
	if err != nil {
		fmt.Println("You are not admin")
		return false
	}
	if isAdmin {
		return true
	}
	return false
}
func (db *DB) InsertJob(name string, company string, description string, added_date time.Time, email string) error {
	ctx := context.Background()
	_, err := db.Pool.Exec(ctx, "INSERT INTO jobs (name,company,description,added_date,contacts) VALUES ($1, $2, $3, $4, $5)", name, company, description, added_date, email)
	return err
}
func (db *DB) GetUsersEmail() ([]string, error) {
	ctx := context.Background()
	var users []string
	rows, err := db.Pool.Query(ctx, "SELECT email FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		users = append(users, email)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
func (db *DB) ChatCreate(userid string, created_at time.Time) error {
	ctx := context.Background()
	_, err := db.Pool.Exec(ctx, "INSERT INTO chats (user_id,created_at) VALUES ($1,$2)", userid, created_at)
	return err
}

//func (db *DB) CheckExistChat(userid string) error {
//	ctx := context.Background()
//	_, err := db.Pool.Exec(ctx, "SELECT ")
//}
