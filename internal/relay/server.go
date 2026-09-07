package relay

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"author/pkg/protocol"
)

type Config struct {
	Port      string
	DBPath    string
	StaticDir string // Optional path to serve web assets from disk (not embedded)
	Version   string
}

type Server struct {
	cfg     Config
	store   *Store
	handler *Handler
	server  *http.Server
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "./data/author.db"
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}

	store, err := NewStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize relay store: %w", err)
	}

	broker := NewBroker()
	handler := NewHandler(store, broker, cfg.Version)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/v1/claim", handler.HandleClaim)
	mux.HandleFunc("/v1/resolve/", handler.HandleResolve)
	mux.HandleFunc("/v1/rotate", handler.HandleRotate)
	mux.HandleFunc("/v1/revoke", handler.HandleRevoke)
	mux.HandleFunc("/v1/send", handler.HandleSend)
	mux.HandleFunc("/v1/inbox", handler.HandleInbox)
	mux.HandleFunc("/v1/ack", handler.HandleAck)
	mux.HandleFunc("/v1/events", handler.HandleEvents)

	// Serve external static assets from disk if configured (not embedded into binary)
	if cfg.StaticDir != "" {
		if stat, err := os.Stat(cfg.StaticDir); err == nil && stat.IsDir() {
			mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
		}
	}

	// Wrap middleware: CORS -> Logging -> Mux
	var chain http.Handler = mux
	chain = LoggingMiddleware(chain)
	chain = CORSMiddleware(chain)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           chain,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return &Server{
		cfg:     cfg,
		store:   store,
		handler: handler,
		server:  srv,
	}, nil
}

func (s *Server) Run() error {
	// Start background worker for nonces pruning (prune older than 10 mins)
	stopPruning := make(chan struct{})
	defer close(stopPruning)
	go s.nonceCleanupWorker(stopPruning)

	// Server shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("Starting Identity Relay on port :%s (db: %s)...", s.cfg.Port, s.cfg.DBPath)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case sig := <-stop:
		log.Printf("Received signal %v. Gracefully shutting down...", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	return s.store.Close()
}

func (s *Server) Close() error {
	return s.store.Close()
}

func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) nonceCleanupWorker(stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cutoff := protocol.CurrentUnix() - 600 // 10 minutes ago
			if n, err := s.store.PruneNonces(cutoff); err == nil && n > 0 {
				log.Printf("[cleaner] Pruned %d expired replay nonces", n)
			}
		case <-stop:
			return
		}
	}
}
