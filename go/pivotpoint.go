package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RedirectRule represents configuration for a single redirect rule
type RedirectRule struct {
	TargetURL     string
	RedirectType  int
	PreservePath  bool
	HTTPSFirst    bool
	parsedTarget  *url.URL
	parsedTargetM sync.Once
}

// ServerConfig holds the server configuration
type ServerConfig struct {
	HTTPPort  int
	HTTPSPort int
	Host      string
}

// RedirectHandler handles HTTP requests and performs redirects based on Host header
type RedirectHandler struct {
	redirectionRules map[string]*RedirectRule
	serverConfig     *ServerConfig
}

// SNIServer represents a TCP server with SNI support
type SNIServer struct {
	httpServer  *http.Server
	httpsServer *http.Server
	certMaps    map[string]*tls.Config
	defaultCert *tls.Config
}

// NewRedirectRule creates a new RedirectRule with default values
func NewRedirectRule(targetURL string) *RedirectRule {
	return &RedirectRule{
		TargetURL:    targetURL,
		RedirectType: http.StatusMovedPermanently,
		PreservePath: true,
		HTTPSFirst:   false,
	}
}

// GetRedirectURL returns the final redirect URL based on the configuration
func (r *RedirectRule) GetRedirectURL(originalPath string) string {
	r.parsedTargetM.Do(func() {
		parsed, err := url.Parse(r.TargetURL)
		if err != nil {
			log.Printf("Error parsing target URL: %v", err)
			return
		}
		r.parsedTarget = parsed
	})

	if r.parsedTarget == nil {
		return r.TargetURL
	}

	if r.PreservePath {
		return fmt.Sprintf("%s://%s%s", r.parsedTarget.Scheme, r.parsedTarget.Host, originalPath)
	}
	return r.TargetURL
}

// ServeHTTP implements the http.Handler interface
func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0] // Remove port if present

	// Get the redirect rule for this host
	rule, exists := h.redirectionRules[host]
	if !exists {
		rule, exists = h.redirectionRules["default"]
		if !exists {
			http.Error(w, "Not Found", http.StatusNotFound)
			log.Printf("No destination found for host: %s", host)
			return
		}
	}

	// Handle HTTPS first redirect if needed
	if rule.HTTPSFirst && r.TLS == nil {
		httpsURL := fmt.Sprintf("https://%s:%d%s", host, h.serverConfig.HTTPSPort, r.URL.Path)
		if r.URL.RawQuery != "" {
			httpsURL += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		log.Printf("Redirected HTTP request for %s%s to HTTPS %s", r.Host, r.URL.Path, httpsURL)
		return
	}

	// Perform the redirect
	redirectURL := rule.GetRedirectURL(r.URL.Path)
	if r.URL.RawQuery != "" {
		redirectURL += "?" + r.URL.RawQuery
	}

	http.Redirect(w, r, redirectURL, rule.RedirectType)
	log.Printf("Redirected %s%s to %s (type: %d)", r.Host, r.URL.Path, redirectURL, rule.RedirectType)
}

// loadRedirectionRules loads and parses the redirect configuration file
func loadRedirectionRules(configFile string) (map[string]*RedirectRule, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}
	defer file.Close()

	rules := make(map[string]*RedirectRule)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			log.Printf("Invalid line in config: %s", line)
			continue
		}

		host := parts[0]
		targetURL := parts[1]
		rule := NewRedirectRule(targetURL)

		// Parse options
		for _, opt := range parts[2:] {
			optParts := strings.Split(opt, "=")
			if len(optParts) != 2 {
				log.Printf("Invalid option: %s", opt)
				continue
			}

			switch optParts[0] {
			case "type":
				if redirectType, err := strconv.Atoi(optParts[1]); err == nil {
					if redirectType == http.StatusMovedPermanently || redirectType == http.StatusFound {
						rule.RedirectType = redirectType
					}
				}
			case "preserve_path":
				rule.PreservePath = optParts[1] == "yes"
			case "https_first":
				rule.HTTPSFirst = optParts[1] == "yes"
			}
		}

		rules[host] = rule
	}

	return rules, scanner.Err()
}

// loadCertMappings loads certificate configurations from the specified file
func loadCertMappings(configFile string) (map[string]*tls.Config, *tls.Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening cert config file: %v", err)
	}
	defer file.Close()

	certMaps := make(map[string]*tls.Config)
	var defaultCert *tls.Config
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			log.Printf("Invalid line in cert config: %s", line)
			continue
		}

		host := parts[0]
		certFile := parts[1]
		keyFile := parts[2]

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("Error loading certificate for %s: %v", host, err)
			continue
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		if host == "default" {
			defaultCert = config
		} else {
			certMaps[host] = config
			log.Printf("Loaded certificate for %s: %s", host, certFile)
		}
	}

	return certMaps, defaultCert, scanner.Err()
}

func runServers(config *ServerConfig, rules map[string]*RedirectRule, certMaps map[string]*tls.Config, defaultCert *tls.Config) {
	handler := &RedirectHandler{
		redirectionRules: rules,
		serverConfig:     config,
	}

	httpAddr := fmt.Sprintf("%s:%d", config.Host, config.HTTPPort)
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: handler,
	}

	httpsAddr := fmt.Sprintf("%s:%d", config.Host, config.HTTPSPort)
	httpsServer := &http.Server{
		Addr:    httpsAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if config, ok := certMaps[hello.ServerName]; ok {
					return config, nil
				}
				return defaultCert, nil
			},
		},
	}

	// Create a channel to receive OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(2)

	// Start HTTP server
	go func() {
		defer wg.Done()
		log.Printf("Starting HTTP server on %s", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
		log.Printf("HTTP server closed")
	}()

	// Start HTTPS server
	go func() {
		defer wg.Done()
		log.Printf("Starting HTTPS server on %s", httpsAddr)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v", err)
		}
		log.Printf("HTTPS server closed")
	}()

	// Wait for interrupt signal
	<-stop
	log.Printf("Received shutdown signal, initiating graceful shutdown...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown of both servers
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	}

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTPS server forced to shutdown: %v", err)
	}

	// Wait for servers to finish
	wg.Wait()
	log.Printf("Servers shutdown completed")
}


func main() {
	// Parse command line arguments
	redirectsFile := flag.String("redirects", "", "Redirects configuration file")
	certsFile := flag.String("certs", "", "Certificates configuration file")
	httpPort := flag.Int("http-port", 8080, "HTTP port to listen on")
	httpsPort := flag.Int("https-port", 8443, "HTTPS port to listen on")
	host := flag.String("host", "", "Host to listen on")
	flag.Parse()

	if *redirectsFile == "" || *certsFile == "" {
		log.Fatal("Both --redirects and --certs flags are required")
	}

	// Initialize server configuration
	config := &ServerConfig{
		HTTPPort:  *httpPort,
		HTTPSPort: *httpsPort,
		Host:      *host,
	}

	// Load redirect rules
	rules, err := loadRedirectionRules(*redirectsFile)
	if err != nil {
		log.Fatalf("Error loading redirect rules: %v", err)
	}

	// Load certificate mappings
	certMaps, defaultCert, err := loadCertMappings(*certsFile)
	if err != nil {
		log.Fatalf("Error loading certificate mappings: %v", err)
	}

	runServers(config, rules, certMaps, defaultCert)
}
