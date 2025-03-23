package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
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

// Configuration for a single redirect rule
type RedirectRule struct {
	TargetURL     string
	RedirectType  int
	PreservePath  bool
	HTTPSFirst    bool
	parsedTarget  *url.URL
	parsedTargetM sync.Once
}

type ServerConfig struct {
	HTTPPort  int
	HTTPSPort int
	Host      string
}

// RedirectRules container for optimized rule matching
type RedirectRules struct {
	exactRules    map[string]*RedirectRule
	wildcardRules map[string]*RedirectRule
	defaultRule   *RedirectRule
}

// NewRedirectRules creates a new RedirectRules container
func NewRedirectRules() *RedirectRules {
	return &RedirectRules{
		exactRules:    make(map[string]*RedirectRule),
		wildcardRules: make(map[string]*RedirectRule),
	}
}

// Handler for HTTP requests and performs redirects based on Host header
type RedirectHandler struct {
	redirectionRules *RedirectRules
	serverConfig     *ServerConfig
}

// Server with SNI support (to be used later)
type SNIServer struct {
	httpServer  *http.Server
	httpsServer *http.Server
	certMaps    map[string]*tls.Config
	defaultCert *tls.Config
}

// Create a new RedirectRule with default values
func NewRedirectRule(targetURL string) *RedirectRule {
	return &RedirectRule{
		TargetURL:    targetURL,
		RedirectType: http.StatusMovedPermanently,
		PreservePath: true,
		HTTPSFirst:   false,
	}
}

// AddRule adds a rule to the appropriate collection based on pattern type
func (r *RedirectRules) AddRule(pattern string, rule *RedirectRule) {
	if pattern == "default" {
		r.defaultRule = rule
	} else if strings.HasPrefix(pattern, "*.") {
		r.wildcardRules[pattern[2:]] = rule // Store without the "*." prefix
	} else {
		r.exactRules[pattern] = rule
	}
}

// GetRule gets the matching rule for a host using optimized matching
func (r *RedirectRules) GetRule(host string) *RedirectRule {
	// Exact match
	if rule, exists := r.exactRules[host]; exists {
		return rule
	}

	// Wildcard match
	domainParts := strings.Split(host, ".")
	for i := range len(domainParts) - 1 {
		suffix := strings.Join(domainParts[i:], ".")
		if rule, exists := r.wildcardRules[suffix]; exists {
			return rule
		}
	}

	// Default rule
	return r.defaultRule
}

// Get the final redirect URL based on the configuration
func (r *RedirectRule) GetRedirectURL(originalPath string) string {
	r.parsedTargetM.Do(func() {
		parsed, err := url.Parse(r.TargetURL)
		if err != nil {
			slog.Error("Error parsing target URL", "error", err)
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

// Implement the http.Handler interface for the RedirectHandler
func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0] // Remove port if present

	rule := h.redirectionRules.GetRule(host)
	if rule != nil {
		h.applyRedirect(w, r, rule, host)
		return
	}

	http.Error(w, "Not Found", http.StatusNotFound)
	slog.Error("No destination found for host", "host", host)
}

// Apply the redirect rule to the current request
func (h *RedirectHandler) applyRedirect(w http.ResponseWriter, r *http.Request, rule *RedirectRule, host string) {
	// Handle HTTPS first redirect if needed
	if rule.HTTPSFirst && r.TLS == nil {
		httpsURL := fmt.Sprintf("https://%s:%d%s", host, h.serverConfig.HTTPSPort, r.URL.Path)
		if r.URL.RawQuery != "" {
			httpsURL += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		slog.Info("Redirected HTTP request", "host", r.Host, "path", r.URL.Path, "httpsURL", httpsURL)
		return
	}

	// Perform the redirect for real
	redirectURL := rule.GetRedirectURL(r.URL.Path)
	if r.URL.RawQuery != "" {
		redirectURL += "?" + r.URL.RawQuery
	}

	http.Redirect(w, r, redirectURL, rule.RedirectType)
	slog.Info("Redirected", "host", r.Host, "path", r.URL.Path, "redirectURL", redirectURL, "type", rule.RedirectType)
}

// Load and parse the redirect configuration file
func loadRedirectionRules(configFile string) (*RedirectRules, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}
	defer file.Close()

	rules := NewRedirectRules()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			slog.Error("Invalid line in config", "line", line)
			continue
		}

		host := parts[0]
		targetURL := parts[1]
		rule := NewRedirectRule(targetURL)
		slog.Debug("Adding rule", "host", host, "target", targetURL)

		// Parse options
		for _, opt := range parts[2:] {
			optParts := strings.Split(opt, "=")
			if len(optParts) != 2 {
				slog.Error("Invalid option", "option", opt)
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

		rules.AddRule(host, rule)
	}

	return rules, scanner.Err()
}

// Load certificate configurations from the specified file
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
			slog.Error("Invalid line in cert config", "line", line)
			continue
		}

		host := parts[0]
		certFile := parts[1]
		keyFile := parts[2]

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			slog.Error("Error loading certificate", "host", host, "error", err)
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
			slog.Debug("Loaded certificate", "host", host, "cert", certFile)
		}
	}

	return certMaps, defaultCert, scanner.Err()
}

// Run the HTTP and HTTPS servers in parallel
func runServers(config *ServerConfig, rules *RedirectRules, certMaps map[string]*tls.Config, defaultCert *tls.Config) {
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

	// Create a channel to receive SIGINT and SIGTERM signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(2)

	// Start HTTP server
	go func() {
		defer wg.Done()
		slog.Info("Starting HTTP server", "addr", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
		}
		slog.Info("HTTP server closed")
	}()

	// Start HTTPS server
	go func() {
		defer wg.Done()
		slog.Info("Starting HTTPS server", "addr", httpsAddr)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS server error", "error", err)
		}
		slog.Info("HTTPS server closed")
	}()

	// Wait for interrupt signal
	<-stop
	slog.Info("Received shutdown signal, initiating graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown of both servers
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server forced to shutdown", "error", err)
	}

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTPS server forced to shutdown", "error", err)
	}

	// Wait for servers to finish
	wg.Wait()
	slog.Info("Servers shutdown completed")
}

func main() {
	// Parse command line arguments
	var redirectsFile string
	var certsFile string
	var httpPort int
	var httpsPort int
	var host string
	var logLevel string
	flag.StringVar(&redirectsFile, "redirects", "", "Redirects configuration file")
	flag.StringVar(&redirectsFile, "r", "", "Redirects configuration file")
	flag.StringVar(&certsFile, "certs", "", "Certificates configuration file")
	flag.StringVar(&certsFile, "c", "", "Certificates configuration file")
	flag.IntVar(&httpPort, "http-port", 8080, "HTTP port to listen on")
	flag.IntVar(&httpPort, "p", 8080, "HTTP port to listen on")
	flag.IntVar(&httpsPort, "https-port", 8443, "HTTPS port to listen on")
	flag.StringVar(&host, "host", "", "Host to listen on")
	flag.StringVar(&host, "H", "", "Host to listen on")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&logLevel, "l", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	var level slog.Level
	err := level.UnmarshalText([]byte(logLevel))
	if err != nil {
		slog.Error("Invalid log level", "error", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})))

	if redirectsFile == "" || certsFile == "" {
		slog.Error("Both --redirects and --certs flags are required")
		os.Exit(1)
	}

	// Initialize server configuration
	config := &ServerConfig{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
		Host:      host,
	}

	// Load redirect rules
	rules, err := loadRedirectionRules(redirectsFile)
	if err != nil {
		slog.Error("Error loading redirect rules", "error", err)
		os.Exit(1)
	}

	// Load certificate mappings
	certMaps, defaultCert, err := loadCertMappings(certsFile)
	if err != nil {
		slog.Error("Error loading certificate mappings", "error", err)
		os.Exit(1)
	}

	runServers(config, rules, certMaps, defaultCert)
}
