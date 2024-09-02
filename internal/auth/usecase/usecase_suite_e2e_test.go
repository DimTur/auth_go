package usecase_test

import (
	"auth_go_hw/config"
	"auth_go_hw/internal/auth/repository"
	"auth_go_hw/internal/auth/usecase"
	"auth_go_hw/internal/gateway/http/gen"
	"auth_go_hw/internal/pkg/crypto"
	"auth_go_hw/internal/pkg/jwt"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/suite"
)

type httpGatewaySuite struct {
	suite.Suite
	cfg        *config.Config
	log        *slog.Logger
	storage    repository.SQLLiteStorage
	jwtManager *jwt.JWTManager
	httpServer *http.Server
	httpGwAddr string
}

func TestHttpGatewaySuite(t *testing.T) {
	suite.Run(t, new(httpGatewaySuite))
}

func (s *httpGatewaySuite) SetupSuite() {
	var err error

	// Initialize logger
	s.log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s.Require().NoError(err)

	// Load configuration
	configPath := "../../../config.yaml"
	s.cfg, err = config.Parse(configPath)
	s.Require().NoError(err)

	// Initialize storage
	s.storage, err = repository.New("/home/ubuntu/Desktop/go_to_middle/auth_go_hw/cmd/users.sql")
	s.Require().NoError(err)

	// Initialize components
	passwordHasher := crypto.NewPasswordHasher()
	s.jwtManager, err = jwt.NewJWTManager(
		s.cfg.JWT.Issuer,
		s.cfg.JWT.AccessExpiresIn,
		s.cfg.JWT.RefreshExpiresIn,
		[]byte(s.cfg.JWT.PublicKeyTest),
		[]byte(s.cfg.JWT.PrivateKeyTest))
	s.Require().NoError(err)

	// Set up http server and Gateway
	s.httpGwAddr = ":9090"
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	authHandlers := usecase.NewUseCase(
		&s.storage,
		passwordHasher,
		s.jwtManager,
	)
	s.httpServer = &http.Server{
		Addr:         s.httpGwAddr,
		ReadTimeout:  s.cfg.HTTPServer.Timeout,
		WriteTimeout: s.cfg.HTTPServer.Timeout,
		Handler:      gen.HandlerFromMux(gen.NewStrictHandler(authHandlers, nil), router),
	}
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.Require().NoError(err)
		}
	}()
}

func (s *httpGatewaySuite) TearDownSuite() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.T().Fatalf("Failed to shutdown server: %v", err)
		}
	}

	if err := s.storage.Close(); err != nil {
		s.T().Fatalf("Failed to close storage: %v", err)
	}
}

func (s *httpGatewaySuite) TestRegisterUser() {
	regUserReq := &gen.PostRegisterRequestObject{
		Body: &gen.PostRegisterJSONRequestBody{
			Username: "user1",
			Password: "validpassword",
		},
	}

	jsonReqBody, err := json.Marshal(regUserReq.Body)
	s.Require().NoError(err)

	res, err := http.Post(
		fmt.Sprintf("http://localhost%s/register", s.httpGwAddr),
		"application/json",
		bytes.NewBuffer(jsonReqBody),
	)
	s.Require().NoError(err)
	defer res.Body.Close()

	s.Equal(http.StatusCreated, res.StatusCode)

	registerResModel := &gen.PostRegister201JSONResponse{}
	bodyRes, err := io.ReadAll(res.Body)
	s.Require().NoError(err)

	err = json.Unmarshal(bodyRes, registerResModel)
	s.Require().NoError(err)

	s.Equal(registerResModel.Username, regUserReq.Body.Username)
}

// All tests bellow will fail.
// Reason: the app needs to be improved and such cases taken into account
func (s *httpGatewaySuite) TestRegisterDuplicateUser() {
	regUserReq := &gen.PostRegisterRequestObject{
		Body: &gen.PostRegisterJSONRequestBody{
			Username: "user2",
			Password: "validpassword",
		},
	}

	jsonReqBody, err := json.Marshal(regUserReq.Body)
	s.Require().NoError(err)

	res, err := http.Post(
		fmt.Sprintf("http://localhost%s/register", s.httpGwAddr),
		"application/json",
		bytes.NewBuffer(jsonReqBody),
	)
	s.Require().NoError(err)
	defer res.Body.Close()
	s.Equal(http.StatusCreated, res.StatusCode)

	res, err = http.Post(
		fmt.Sprintf("http://localhost%s/register", s.httpGwAddr),
		"application/json",
		bytes.NewBuffer(jsonReqBody),
	)
	s.Require().NoError(err)
	defer res.Body.Close()

	s.Equal(http.StatusConflict, res.StatusCode)
}

func (s *httpGatewaySuite) TestRegisterUserWithInvalidData() {
	invalidRequests := []struct {
		body         *gen.PostRegisterJSONRequestBody
		expectedCode int
	}{
		{body: &gen.PostRegisterJSONRequestBody{Username: "", Password: "validpassword"}, expectedCode: http.StatusBadRequest},
		{body: &gen.PostRegisterJSONRequestBody{Username: "user3", Password: ""}, expectedCode: http.StatusBadRequest},
		{body: &gen.PostRegisterJSONRequestBody{Username: "", Password: ""}, expectedCode: http.StatusBadRequest},
	}

	for _, req := range invalidRequests {
		jsonReqBody, err := json.Marshal(req.body)
		s.Require().NoError(err)

		res, err := http.Post(
			fmt.Sprintf("http://localhost%s/register", s.httpGwAddr),
			"application/json",
			bytes.NewBuffer(jsonReqBody),
		)
		s.Require().NoError(err)
		defer res.Body.Close()

		s.Equal(req.expectedCode, res.StatusCode)
	}
}

func (s *httpGatewaySuite) TestRegisterUserWithWeakPassword() {
	weakPasswordReq := &gen.PostRegisterRequestObject{
		Body: &gen.PostRegisterJSONRequestBody{
			Username: "user4",
			Password: "123", // Easy password
		},
	}

	jsonReqBody, err := json.Marshal(weakPasswordReq.Body)
	s.Require().NoError(err)

	res, err := http.Post(
		fmt.Sprintf("http://localhost%s/register", s.httpGwAddr),
		"application/json",
		bytes.NewBuffer(jsonReqBody),
	)
	s.Require().NoError(err)
	defer res.Body.Close()

	s.Equal(http.StatusBadRequest, res.StatusCode)
}
