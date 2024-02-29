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
		return ErrUserAlreadyExists // You should define this error
	}
	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, name, password,confirmation_token,token_expiration) VALUES ($1, $2, $3, $4, $5)", email, name, string(hashedPassword), confirmationToken, tokenExpiration)
	return err
}
func (db *DB) GetUserByEmail(email string) (*User, error) {
	ctx := context.Background()
	user := &User{}

	err := db.Pool.QueryRow(ctx, "SELECT email, name, password FROM users WHERE email=$1", email).Scan(&user.Email, &user.Name, &user.Password)
	if err != nil {
		// This will print more detailed error information
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

	// Optionally, check if the token is expired
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
