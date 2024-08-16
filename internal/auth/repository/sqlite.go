package repository

import (
	"auth_go_hw/internal/auth/entity"
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLLiteStorage struct {
	db *sql.DB
}

func New(dbPath string) (SQLLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return SQLLiteStorage{}, err
	}

	// Create table users
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	// Create index users
	_, err = db.Exec(`
	CREATE INDEX IF NOT EXISTS idx_username ON users(username);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	// Create table refresh_tokens
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	// Create index refresh_tokens
	_, err = db.Exec(`
	CREATE INDEX IF NOT EXISTS idx_user_id ON refresh_tokens(user_id);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	return SQLLiteStorage{db: db}, nil
}

func (s *SQLLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLLiteStorage) RegisterUser(ctx context.Context, u entity.UserAccount) error {
	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO users(username, password) VALUES(?,?)`)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(u.Username, u.Password); err != nil {
		return err
	}

	return nil
}

func (s *SQLLiteStorage) FindUserByLogin(ctx context.Context, username string) (entity.UserAccount, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT id, password FROM users WHERE username = ?`)
	if err != nil {
		return entity.UserAccount{}, err
	}

	var idFromDB, pswFromDB string

	if err := stmt.QueryRow(username).Scan(&idFromDB, &pswFromDB); err != nil {
		return entity.UserAccount{}, err
	}

	return entity.UserAccount{
		Username: username,
		Password: pswFromDB,
		UserID:   idFromDB,
	}, nil
}

// TODO replace to TokenRepo
func (s *SQLLiteStorage) SaveRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES(?,?,?)`)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(userID, token, expiresAt); err != nil {
		return err
	}

	return nil
}

// TODO replace to TokenRepo
func (s *SQLLiteStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	stmt, err := s.db.PrepareContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(token); err != nil {
		return nil
	}

	return nil
}

// TODO replace to TokenRepo
func (s *SQLLiteStorage) FindRefreshToken(ctx context.Context, userID string) (entity.RefreshToken, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT token FROM refresh_tokens WHERE user_id = ?`)
	if err != nil {
		return entity.RefreshToken{}, err
	}

	var tokenFromDB string

	err = stmt.QueryRow(userID).Scan(&tokenFromDB)
	if err != nil {
		if err == sql.ErrNoRows {
			return entity.RefreshToken{
				Token:  "",
				UserID: userID,
			}, nil
		}
		return entity.RefreshToken{}, err
	}

	return entity.RefreshToken{
		Token:  tokenFromDB,
		UserID: userID,
	}, nil
}
