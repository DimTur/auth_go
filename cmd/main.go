package main

import (
	"auth_go_hw/cmd/commands"
	"context"
	"log"
)

func main() {
	ctx := context.Background()

	cmd := commands.NewServeCmd()

	if err := cmd.ExecuteContext(ctx); err != nil {
		log.Fatalf("smth went wrong: %s", err)
	}
}
