package main

import (
	"log"
	"os"
	"path/filepath"

	"author/internal/relay"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	dbPath := filepath.Join(dataDir, "author.db")

	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		if stat, err := os.Stat("./web"); err == nil && stat.IsDir() {
			staticDir = "./web"
		}
	}

	srv, err := relay.NewServer(relay.Config{
		Port:      port,
		DBPath:    dbPath,
		StaticDir: staticDir,
		Version:   "0.1.0",
	})
	if err != nil {
		log.Fatalf("Failed to initialize relay: %v", err)
	}

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
