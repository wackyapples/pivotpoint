package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const usage = `Usage: pivotpoint [options]

PivotPoint server

Options:
  -h, --help
    	Show this help message
  --config, -c CONFIG
    	Configuration file
  --http-port, -p HTTP_PORT
    	HTTP port to listen on (default: 8080)
  --https-port, -s HTTPS_PORT
    	HTTPS port to listen on (default: 8443)
  --host, -H HOST
    	Host to listen on (default: all interfaces)
  --log-level, -l {debug,info,warn,error}
    	Log level (debug, info, warn, error)
  --log-format, -f {text,json}
    	Log format (text, json)
`

// Configuration for a single redirect rule
type RedirectRule struct {
	TargetURL     string
	RedirectType  int
	PreservePath  bool
	HTTPSFirst    bool
	parsedTarget  *url.URL
	parsedTargetM sync.Once
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
func loadRedirectionRules(configData TOMLData) (*RedirectRules, error) {

	redirectConfigs, err := ParseRedirectConfigs(configData)
	if err != nil {
		return nil, fmt.Errorf("error parsing redirect configs: %v", err)
	}

	rules := NewRedirectRules()
	for _, config := range redirectConfigs {
		rule := NewRedirectRule(config.TargetURL)
		rule.RedirectType = config.RedirectType
		rule.PreservePath = config.PreservePath
		rule.HTTPSFirst = config.HTTPSFirst
		rules.AddRule(config.SourceDomain, rule)
		slog.Debug("Added redirect rule",
			"source", config.SourceDomain,
			"target", config.TargetURL,
			"type", config.RedirectType,
			"preserve_path", config.PreservePath,
			"https_first", config.HTTPSFirst)
	}

	return rules, nil
}

// Load certificate configurations from the specified file
func loadCertMappings(configData TOMLData) (map[string]*tls.Config, *tls.Config, error) {
	certConfigs, err := ParseCertConfigs(configData)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate configs: %v", err)
	}

	certMaps := make(map[string]*tls.Config)
	var defaultCert *tls.Config

	for _, config := range certConfigs {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			slog.Error("Error loading certificate",
				"domain", config.Domain,
				"error", err)
			continue
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		if config.Domain == "default" {
			defaultCert = tlsConfig
		} else {
			certMaps[config.Domain] = tlsConfig
			slog.Debug("Loaded certificate",
				"domain", config.Domain,
				"cert_file", config.CertFile)
		}
	}

	return certMaps, defaultCert, nil
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
	var configFile string
	var httpPort int
	var httpsPort int
	var host string
	var logLevel string
	var logFormat string
	flag.StringVar(&configFile, "config", "", "Configuration file")
	flag.StringVar(&configFile, "c", "", "Configuration file")
	flag.IntVar(&httpPort, "http-port", 0, "HTTP port to listen on")
	flag.IntVar(&httpPort, "p", 0, "HTTP port to listen on")
	flag.IntVar(&httpsPort, "https-port", 0, "HTTPS port to listen on")
	flag.IntVar(&httpsPort, "s", 0, "HTTPS port to listen on")
	flag.StringVar(&host, "host", "", "Host to listen on")
	flag.StringVar(&host, "H", "", "Host to listen on")
	flag.StringVar(&logLevel, "log-level", "", "Log level (debug, info, warn, error)")
	flag.StringVar(&logLevel, "l", "", "Log level (debug, info, warn, error)")
	flag.StringVar(&logFormat, "log-format", "", "Log format (text, json)")
	flag.StringVar(&logFormat, "f", "", "Log format (text, json)")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}
	flag.Parse()

	// Parse log level from CLI if provided
	var cliLogLevel slog.Level
	if logLevel != "" {
		err := cliLogLevel.UnmarshalText([]byte(logLevel))
		if err != nil {
			slog.Error("Invalid log level", "error", err)
			os.Exit(1)
		}
	}

	if configFile == "" {
		slog.Error("Both --config flag is required")
		os.Exit(1)
	}

	// Load configuration data from file
	file, err := os.Open(configFile)
	if err != nil {
		slog.Error("Error opening config file", "error", err)
		os.Exit(1)
	}
	defer file.Close()

	configData, err := ParseConfig(file)
	if err != nil {
		slog.Error("Error loading config data", "error", err)
		os.Exit(1)
	}

	// Load server config from TOML
	var baseConfig *ServerConfig
	baseConfig, err = ParseServerConfig(configData)
	if err != nil {
		slog.Error("Error parsing server config", "error", err)
		os.Exit(1)
	}

	// Merge CLI options with config file options
	config := MergeServerConfig(baseConfig, httpPort, httpsPort, host, cliLogLevel, logFormat)

	// Set up logging based on the merged config
	var handler slog.Handler
	if config.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.LogLevel,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.LogLevel,
		})
	}
	slog.SetDefault(slog.New(handler))

	// Log the final configuration
	slog.Info("Server configuration",
		"http_port", config.HTTPPort,
		"https_port", config.HTTPSPort,
		"host", config.Host,
		"log_level", config.LogLevel,
		"log_format", config.LogFormat)

	rules, err := loadRedirectionRules(configData)
	if err != nil {
		slog.Error("Error loading redirect rules", "error", err)
		os.Exit(1)
	}

	certMaps, defaultCert, err := loadCertMappings(configData)
	if err != nil {
		slog.Error("Error loading certificate mappings", "error", err)
		os.Exit(1)
	}

	runServers(config, rules, certMaps, defaultCert)
}
