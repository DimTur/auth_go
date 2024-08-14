package commands

import (
	"auth_go_hw/config"
	"auth_go_hw/internal/buildinfo"
	"auth_go_hw/internal/handlers"
	"auth_go_hw/internal/storage"
	"context"
	"fmt"
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

			s, err := storage.New("./users.sql")
			if err != nil {
				return err
			}

			cfg, err := config.Parse("../config.yaml")
			if err != nil {
				return err
			}

			slog.Info("loaded cfg", slog.Any("cfg", cfg))

			router.Post("/register", handlers.RegisterHandler(&s))
			router.Post("/login", handlers.LoginHandler(&s))
			router.Get("/build", buildinfo.BuildInfoHandler(buildinfo.New()))

			httpServer := http.Server{
				Addr:         cfg.HTTPServer.Address,
				ReadTimeout:  cfg.HTTPServer.Timeout,
				WriteTimeout: cfg.HTTPServer.Timeout,
				Handler:      router,
			}

			go func() {
				if err := httpServer.ListenAndServe(); err != nil {
					log.Error("ListenAndServe", slog.Any("err", err))
				}
			}()
			log.Info("server listening: 8080")

			<-ctx.Done()

			closeCtx, _ := context.WithTimeout(context.Background(), time.Second)
			if err := httpServer.Shutdown(closeCtx); err != nil {
				return fmt.Errorf("http closing err: %s", err)
			}
			// close db connection
			// etc

			return nil
		},
	}
	return c
}
