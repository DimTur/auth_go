package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// TODO to models package
type UserAccount struct {
	Username string
	Password string
}

type SQLLiteStorage struct {
	db *sql.DB
}

func New(dbPath string) (SQLLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return SQLLiteStorage{}, err
	}
	stmt, err := db.Prepare(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		password TEXT NOT NULL);
	CREATE INDEX IF NOT EXISTS idx_username ON users(username);
	`)
	if err != nil {
		return SQLLiteStorage{}, err
	}

	_, err = stmt.Exec()
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}
	return SQLLiteStorage{db: db}, nil
}

func (s *SQLLiteStorage) RegisterUser(ctx context.Context, u UserAccount) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO users(username, password) VALUES(?,?)`)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(u.Username, hashedPassword); err != nil {
		return err
	}

	return nil
}

func (s *SQLLiteStorage) Login(ctx context.Context, username, password string) (UserAccount, error) {

	stmt, err := s.db.PrepareContext(ctx, `SELECT password FROM users WHERE username = ?`)
	if err != nil {
		return UserAccount{}, err
	}

	var pswFromBd string

	if err := stmt.QueryRow(username).Scan(&pswFromBd); err != nil {
		return UserAccount{}, err
	}

	// log.Println(pswFromBd)

	return UserAccount{
		Username: username,
	}, nil
}
