package main

import (
	"context"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
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

func (db *DB) RegisterUser(email, name, password string) error {
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

	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, name, password) VALUES ($1, $2, $3)", email, name, string(hashedPassword))
	return err
}
func (db *DB) GetUserByEmail(email string) (*User, error) {
	ctx := context.Background()
	user := &User{}

	// Adjust the SQL query based on your table structure.
	err := db.Pool.QueryRow(ctx, "SELECT email, name, password FROM users WHERE email=$1", email).Scan(&user.Email, &user.Name, &user.password)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errBadCredentials
		}
		return nil, err
	}

	return user, nil
}
func (db *DB) GetUserByConfirmToken(token string) (*User, error) {
	ctx := context.Background()
	user := &User{}
	// Assuming `db` is your database connection object and `User` is your user model
	// Replace `users` with your actual users table name
	err := db.Pool.QueryRow(ctx, "SELECT * FROM users WHERE confirmation_token = $1", token).Scan(&user.Email, &user.Name, &user.ConfirmToken, &user.ConfirmationTokenExpiration)

	if err != nil {
		// Handle error (e.g., token not found or database error)
		return nil, err
	}

	// Optionally, check if the token is expired
	if user.ConfirmationTokenExpiration.Before(time.Now()) {
		return nil, errors.New("confirmation token is expired")
	}

	return user, nil
}
