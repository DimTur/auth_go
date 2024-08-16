package commands

import (
	"auth_go_hw/config"
	"auth_go_hw/internal/auth/repository"
	"auth_go_hw/internal/auth/usecase"
	"auth_go_hw/internal/buildinfo"
	"auth_go_hw/internal/gateway/http/gen"
	"auth_go_hw/internal/pkg/crypto"
	"auth_go_hw/internal/pkg/jwt"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var configPath string

	c := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"s"},
		Short:   "Start API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()

			router := chi.NewRouter()
			router.Use(middleware.RequestID)
			router.Use(middleware.Recoverer)
			router.Use(middleware.Logger)

			cfg, err := config.Parse(configPath)
			if err != nil {
				return err
			}

			slog.Info("loaded cfg", slog.Any("cfg", cfg))

			storage, err := repository.New("./users.sql")
			if err != nil {
				return err
			}

			passwordHasher := crypto.NewPasswordHasher()
			jwtManager, err := jwt.NewJWTManager(
				cfg.JWT.Issuer,
				cfg.JWT.AccessExpiresIn,
				cfg.JWT.RefreshExpiresIn,
				[]byte(cfg.JWT.PublicKey),
				[]byte(cfg.JWT.PrivateKey),
			)
			if err != nil {
				return err
			}

			useCase := usecase.NewUseCase(&storage,
				passwordHasher,
				jwtManager,
				buildinfo.New())

			httpServer := http.Server{
				Addr:         cfg.HTTPServer.Address,
				ReadTimeout:  cfg.HTTPServer.Timeout,
				WriteTimeout: cfg.HTTPServer.Timeout,
				Handler:      gen.HandlerFromMux(gen.NewStrictHandler(useCase, nil), router),
			}

			go func() {
				if err := httpServer.ListenAndServe(); err != nil {
					log.Error("ListenAndServe", slog.Any("err", err))
				}
			}()
			log.Info("server listening:", slog.Any("port", cfg.HTTPServer.Address))

			<-ctx.Done()

			closeCtx, _ := context.WithTimeout(context.Background(), time.Second)
			if err := httpServer.Shutdown(closeCtx); err != nil {
				log.Error("httpServer.Shutdown", slog.Any("err", err))
			}

			if err := storage.Close(); err != nil {
				log.Error("storage.Close", slog.Any("err", err))
			}

			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "path to config")
	return c
}
