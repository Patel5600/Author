package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	url := os.Getenv("PING_URL")
	if url == "" {
		url = "https://author-relay.onrender.com/health"
	}

	client := http.Client{Timeout: 20 * time.Second}
	fmt.Printf("Pinging relay health: %s\n", url)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ping failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Relay returned status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	fmt.Printf("Relay is healthy and active (status %d)\n", resp.StatusCode)
}
