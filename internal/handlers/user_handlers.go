package handlers

import (
	"auth_go_hw/internal/storage"
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type RegisterRequest struct {
	Username string `json:"username" validate:"requered,min=3,max=20"`
	Password string `json:"password" validate:"requered,min=3"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"requered,min=3,max=20"`
	Password string `json:"password" validate:"requered,min=3"`
}

type UserRepository interface {
	RegisterUser(ctx context.Context, u storage.UserAccount) error
	Login(ctx context.Context, username, password string) (storage.UserAccount, error)
}

func RegisterHandler(ur UserRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := &RegisterRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "parsing err", http.StatusBadRequest)
			return
		}

		err := ur.RegisterUser(r.Context(), storage.UserAccount{
			Username: req.Username,
			Password: req.Password,
		})
		if err != nil {
			http.Error(w, "reg err", http.StatusBadRequest)
			return
		}
	}
}

func LoginHandler(ur UserRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := &LoginRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "parsing err", http.StatusBadRequest)
			return
		}

		// handle different errors
		account, err := ur.Login(r.Context(), req.Username, req.Password)
		if err != nil {
			http.Error(w, "login err", http.StatusUnauthorized)
			return
		}

		// JWT
		log.Println("account", account)
	}
}

func UserProfileHandler(ur UserRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}
