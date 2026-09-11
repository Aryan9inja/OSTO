package main

import (
	"flag"
	"os"

	"github.com/user/auth-cli-system/internal/cli"
)

func main() {
	defaultServer := os.Getenv("AUTH_SERVER_URL")
	if defaultServer == "" {
		defaultServer = "http://localhost:8080"
	}

	serverURL := flag.String("server", defaultServer, "Authentication backend server URL")
	flag.Parse()

	client := cli.NewAPIClient(*serverURL)
	cli.RunREPL(client)
}
