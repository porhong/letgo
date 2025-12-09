package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProgressCallback is called with progress updates (scanned, total, percentage)
type ProgressCallback func(scanned, total int, percentage float64)

// ScannerConfig holds configuration for endpoint scanning
type ScannerConfig struct {
	BaseURL        string
	MaxThreads     int
	Timeout        time.Duration
	UserAgent      string
	CustomHeaders  map[string]string
	OnProgress     ProgressCallback // Optional callback for progress updates
	TargetLanguages []string         // Optional: filter endpoints by language/framework (e.g., "php", "java", "python", "node", "dotnet")
}

// EndpointResult represents a discovered endpoint
type EndpointResult struct {
	URL              string
	Method           string
	StatusCode       int
	IsLoginPage      bool
	HasLoginForm     bool
	ResponseBody     string
	ContentType      string
	ContentLength    int
	DetectedLanguage string  // Detected language/framework (php, java, python, node, dotnet, etc.)
	IsSSR            bool    // Whether this appears to be a Server-Side Rendered page
	Is404            bool    // Whether this is detected as a 404 page despite 200 status
	IsError          bool    // Whether this endpoint returned an error response (400, 500, or error content)
	ErrorType        string  // Type of error detected (e.g., "404", "403", "500", "invalid", "redirect")
	ConfidenceScore  float64 // Confidence score (0-100) indicating likelihood this is a valid login endpoint
}

// Scanner handles endpoint discovery
type Scanner struct {
	config     ScannerConfig
	results    []EndpointResult
	mu         sync.Mutex
	discovered int32
	validated  int32
	scanned    int32 // Total endpoints scanned
	total      int   // Total endpoints to scan
}

// Common login/auth endpoint patterns (streamlined for high accuracy)
var commonEndpoints = []string{
	// Core login patterns (highest probability)
	"/login",
	"/signin",
	"/sign-in",
	"/auth",
	"/authenticate",

	// Account/User login patterns
	"/account/login",
	"/user/login",
	"/users/login",
	"/users/sign_in",

	// Admin login patterns
	"/admin",
	"/admin/login",
	"/administrator",
	"/administrator/login",

	// WordPress
	"/wp-login.php",
	"/wp-admin",

	// Drupal
	"/user/login",
	"/user",

	// Joomla
	"/administrator/index.php",

	// Laravel
	"/auth/login",

	// Django
	"/accounts/login",
	"/admin/login",

	// Spring Boot / Java
	"/api/auth/login",

	// Dashboard/Portal patterns
	"/dashboard",
	"/dashboard/login",
	"/portal",
	"/portal/login",
	"/console",
	"/console/login",

	// API endpoints (most common versions)
	"/api/login",
	"/api/auth",
	"/api/v1/login",
	"/api/v1/auth",
	"/api/v2/auth",
	"/rest/api/auth",

	// OAuth/OAuth2 patterns
	"/oauth/authorize",
	"/oauth2/authorize",
	"/oauth2/auth",

	// SSO patterns
	"/sso",
	"/sso/login",
	"/saml/login",
	"/cas/login",

	// File extension patterns (common only)
	"/login.php",
	"/login.jsp",
	"/login.aspx",
	"/login.html",
	"/auth.php",
	"/signin.php",

	// Control panels - cPanel
	"/cpanel",
	"/cpanel/",
	"/login/?login_only=1",

	// Control panels - WHM (WebHost Manager)
	"/whm",
	"/whm/",

	// Control panels - Plesk
	"/plesk",
	"/login_up.php",

	// Control panels - DirectAdmin
	"/directadmin",
	"/CMD_LOGIN",

	// Control panels - Webmin
	"/webmin",
	"/session_login.cgi",

	// Control panels - ISPConfig/CWP
	"/login/index.php",

	// Control panels - VestaCP
	"/login/",

	// Database admin panels
	"/phpmyadmin",
	"/phpMyAdmin",
	"/pma",
	"/adminer.php",
	"/adminer",
	"/mysql",
	"/db",
	"/dbadmin",

	// Application servers
	"/manager/html",
	"/tomcat/manager",

	// CI/CD and DevOps tools (most popular)
	"/jenkins/login",
	"/gitlab/users/sign_in",
	"/grafana/login",
	"/kibana/login",

	// Enterprise software
	"/owa/auth/logon.aspx",
}

// Compiled regex patterns for better form detection
var (
	passwordFieldRegex = regexp.MustCompile(`<input[^>]*type=["']password["'][^>]*>`)
	usernameFieldRegex = regexp.MustCompile(`<input[^>]*(?:name|id)=["'](?:username|user|email|login|account)["'][^>]*>`)
	formTagRegex       = regexp.MustCompile(`<form[^>]*>`)
	loginButtonRegex   = regexp.MustCompile(`<(?:button|input)[^>]*(?:type=["']submit["']|value=["'](?:log\s*in|sign\s*in|login|signin)["'])[^>]*>`)
)

// Control panel ports to scan (panel_name: ports)
var controlPanelPorts = map[string][]string{
	"cpanel":      {"2082", "2083"},
	"whm":         {"2086", "2087"},
	"plesk":       {"8443"},
	"directadmin": {"2222"},
	"webmin":      {"10000"},
	"ispconfig":   {"8080", "8081"},
	"cwp":         {"2030", "2031"},
	"vestacp":     {"8083"},
}

// Common subdomain patterns for scanning (optimized for high-value targets)
var commonSubdomains = []string{
	"admin",
	"cpanel",
	"panel",
	"login",
	"auth",
	"portal",
	"api",
}

// Common login form field names
var loginFormFields = []string{
	"username", "user", "user_name", "userName", "user_name", "userid", "user_id", "userId",
	"email", "e-mail", "email_address", "emailAddress", "mail", "emailaddress",
	"login", "login_name", "loginName", "loginid", "login_id", "loginId",
	"account", "account_name", "accountName", "accountid", "account_id",
	"uid", "userid", "user_id", "userId",
	"password", "pass", "passwd", "pwd", "pass_word", "password_hash",
	"secret", "secret_key", "secretKey",
	"pin", "passcode", "pass_code",
	"auth_token", "authToken", "token",
	"phone", "phone_number", "phoneNumber", "mobile", "mobile_number",
}

// Common login-related keywords in response
var loginKeywords = []string{
	"login", "log in", "log-in", "log_in", "sign in", "signin", "sign-in", "sign_in",
	"username", "user name", "user_name", "email", "e-mail", "email address",
	"password", "pass word", "pass_word", "passwd", "pwd",
	"forgot password", "forgot your password", "reset password", "password reset",
	"remember me", "remember me", "keep me signed in", "stay signed in",
	"authentication", "authenticate", "auth", "authorization", "authorize",
	"access", "account", "credentials", "sign in to your account",
	"welcome back", "enter your credentials", "enter credentials",
	"log in to continue", "sign in to continue", "please sign in",
	"please log in", "login required", "authentication required",
	"two factor", "2fa", "two-factor", "multi-factor", "mfa",
	"captcha", "recaptcha", "verify you're human",
	"session", "sign out", "logout", "log out",
	"dashboard", "home", "profile", "settings",
	"invalid", "incorrect", "wrong password", "wrong username",
	"account locked", "account disabled", "suspended",
	"otp", "one time password", "verification code",
	"social login", "google login", "facebook login", "oauth",
	"single sign on", "sso", "saml", "ldap",
}

// Control panel signatures for detection (simplified to most distinctive)
var controlPanelSignatures = map[string][]string{
	"cpanel": {"cpanel", "webmail login", "cpsess"},
	"whm": {"webhost manager", "whm"},
	"plesk": {"plesk", "login_up.php"},
	"directadmin": {"directadmin", "cmd_login"},
	"webmin": {"webmin", "usermin", "virtualmin"},
	"ispconfig": {"ispconfig"},
	"cwp": {"centos web panel", "cwp"},
	"vestacp": {"vesta control panel", "vestacp"},
	"cyberpanel": {"cyberpanel", "openlitespeed"},
}

// New creates a new scanner instance
func New(config ScannerConfig) *Scanner {
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	}
	return &Scanner{
		config:  config,
		results: make([]EndpointResult, 0),
	}
}

// Scan discovers login/auth endpoints
func (s *Scanner) Scan(ctx context.Context) ([]EndpointResult, error) {
	baseURL, err := url.Parse(s.config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Extract domain parts
	host := baseURL.Hostname()
	scheme := baseURL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	// Parse domain to extract base domain (e.g., "example.com" from "sub.example.com")
	domainParts := strings.Split(host, ".")
	var baseDomain string
	if len(domainParts) >= 2 {
		// Take last two parts (e.g., "example.com")
		baseDomain = strings.Join(domainParts[len(domainParts)-2:], ".")
	} else {
		baseDomain = host
	}

	// Generate all URLs to scan (base domain + subdomains)
	endpoints := make([]string, 0)

	// Domains to scan: base domain + common subdomains
	domainsToScan := []string{""} // Empty string means base domain
	domainsToScan = append(domainsToScan, commonSubdomains...)

	for _, subdomain := range domainsToScan {
		// Build clean hostname without port
		var cleanHost string
		if subdomain != "" {
			cleanHost = subdomain + "." + baseDomain
		} else {
			cleanHost = baseDomain
		}
		
		// Standard ports (80/443 based on scheme)
		scanURL := &url.URL{
			Scheme: scheme,
			Host:   cleanHost,
			Path:   "/",
		}

		// Add standard endpoint paths
		for _, endpoint := range commonEndpoints {
			fullURL := scanURL.ResolveReference(&url.URL{Path: strings.TrimPrefix(endpoint, "/")}).String()
			endpoints = append(endpoints, fullURL)
		}

		// Add root path
		endpoints = append(endpoints, scanURL.String())
		
		// For base domain and control panel subdomains, also scan control panel ports
		if subdomain == "" || subdomain == "cpanel" || subdomain == "panel" || subdomain == "admin" {
			// Scan each control panel with its specific ports
			for _, ports := range controlPanelPorts {
				for _, port := range ports {
					// Determine scheme based on port
					portScheme := "http"
					if port == "2083" || port == "2087" || port == "2222" || port == "8443" || port == "8081" || port == "2031" || port == "8083" || port == "10000" {
						portScheme = "https"
					}
					
					portURL := &url.URL{
						Scheme: portScheme,
						Host:   cleanHost + ":" + port,
						Path:   "/",
					}
					endpoints = append(endpoints, portURL.String())
					
					// Add important control panel paths for each port
					cpanelPaths := []string{"login", "cpanel", "whm"}
					for _, path := range cpanelPaths {
						pathURL := portURL.ResolveReference(&url.URL{Path: path}).String()
						endpoints = append(endpoints, pathURL)
					}
				}
			}
		}
	}

	// Set total count for progress tracking
	s.total = len(endpoints)
	s.scanned = 0

	// Create channels for jobs and results
	jobs := make(chan string, len(endpoints))
	results := make(chan EndpointResult, len(endpoints))

	var wg sync.WaitGroup

	// Start progress reporter if callback is set
	var progressTicker *time.Ticker
	var progressStop chan bool
	if s.config.OnProgress != nil {
		progressTicker = time.NewTicker(500 * time.Millisecond) // Update every 500ms
		progressStop = make(chan bool)
		go func() {
			for {
				select {
				case <-progressTicker.C:
					scanned := int(atomic.LoadInt32(&s.scanned))
					total := s.total
					if total > 0 {
						percentage := float64(scanned) / float64(total) * 100
						s.config.OnProgress(scanned, total, percentage)
					}
				case <-progressStop:
					return
				}
			}
		}()
	}

	// Start worker goroutines
	for i := 0; i < s.config.MaxThreads; i++ {
		wg.Add(1)
		go s.worker(ctx, i, jobs, results, &wg)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, endpoint := range endpoints {
			select {
			case <-ctx.Done():
				return
			case jobs <- endpoint:
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results - include endpoints that:
	// 1. Have detected login forms/pages, OR
	// 2. Return valid status codes (2xx, 3xx) from known login endpoint paths
	// But exclude SSR 404 pages, error responses, and filter by target languages if specified
	validResults := make([]EndpointResult, 0)
	seenURLs := make(map[string]bool) // Avoid duplicates

	for result := range results {
		// Skip if we've already seen this URL
		if seenURLs[result.URL] {
			continue
		}
		seenURLs[result.URL] = true

		// Skip if this is a 404 page (especially SSR ones that return 200)
		if result.Is404 {
			continue
		}

		// Skip if this is an error response
		if result.IsError {
			continue
		}

		// Apply language filter if specified
		if len(s.config.TargetLanguages) > 0 {
			matched := false
			for _, targetLang := range s.config.TargetLanguages {
				if strings.EqualFold(result.DetectedLanguage, targetLang) {
					matched = true
					break
				}
			}
			if !matched && result.DetectedLanguage != "" {
				continue
			}
		}

		// Use confidence score threshold for better accuracy
		// Only include results with confidence score >= 30 (configurable threshold)
		const confidenceThreshold = 30.0

		if result.ConfidenceScore >= confidenceThreshold {
			validResults = append(validResults, result)
			continue
		}

		// Alternative: Include if it has strong indicators (form detection)
		if result.HasLoginForm && result.StatusCode >= 200 && result.StatusCode < 400 {
			validResults = append(validResults, result)
		}
	}

	// Stop progress reporter and send final update
	if progressTicker != nil {
		progressTicker.Stop()
		close(progressStop)
		// Send final progress update
		if s.config.OnProgress != nil {
			scanned := int(atomic.LoadInt32(&s.scanned))
			total := s.total
			if total > 0 {
				percentage := float64(scanned) / float64(total) * 100
				s.config.OnProgress(scanned, total, percentage)
			}
		}
	}

	return validResults, nil
}

// worker processes endpoint scanning jobs
func (s *Scanner) worker(ctx context.Context, id int, jobs <-chan string, results chan<- EndpointResult, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: s.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but limit to 5
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	for endpointURL := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			atomic.AddInt32(&s.discovered, 1)

			// Try GET first
			result := s.scanEndpoint(client, endpointURL, "GET")
			if result.StatusCode > 0 {
				atomic.AddInt32(&s.validated, 1)
				results <- result
			}
			atomic.AddInt32(&s.scanned, 1) // Increment scanned count

			// Also try POST for API endpoints
			if strings.Contains(endpointURL, "/api/") || strings.Contains(endpointURL, "/auth") {
				result := s.scanEndpoint(client, endpointURL, "POST")
				if result.StatusCode > 0 {
					results <- result
				}
				// Note: We don't increment scanned again for POST to avoid double counting
			}
		}
	}
}

// scanEndpoint scans a single endpoint
func (s *Scanner) scanEndpoint(client *http.Client, endpointURL, method string) EndpointResult {
	result := EndpointResult{
		URL:    endpointURL,
		Method: method,
	}

	req, err := http.NewRequest(method, endpointURL, nil)
	if err != nil {
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	// Add custom headers
	if s.config.CustomHeaders != nil {
		for key, value := range s.config.CustomHeaders {
			req.Header.Set(key, value)
		}
	}

	// For POST requests, add some form data to test
	if method == "POST" {
		formData := url.Values{}
		formData.Set("username", "test")
		formData.Set("password", "test")
		req.Body = io.NopCloser(strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = int64(len(formData.Encode()))
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = int(resp.ContentLength)

	// Read response body (limit to first 50KB for analysis)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	if err == nil {
		result.ResponseBody = string(bodyBytes)
	}

	// Detect language/framework
	result.DetectedLanguage = s.detectLanguage(result.ResponseBody, endpointURL, resp.Header)
	result.IsSSR = s.isSSRFramework(result.DetectedLanguage, result.ResponseBody)
	result.Is404 = s.is404Page(result.ResponseBody, result.StatusCode, result.IsSSR)

	// Detect errors and invalid responses
	result.IsError, result.ErrorType = s.detectError(result.ResponseBody, result.StatusCode, endpointURL)

	// Analyze if this is a login page (only if not an error)
	if !result.IsError {
		result.IsLoginPage = s.isLoginPage(result.ResponseBody, result.StatusCode)
		result.HasLoginForm = s.hasLoginForm(result.ResponseBody)
	}

	// Calculate confidence score
	result.ConfidenceScore = s.calculateConfidenceScore(&result)

	return result
}

// isLoginPage checks if the response indicates a login page
func (s *Scanner) isLoginPage(body string, statusCode int) bool {
	// Only accept 2xx status codes
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	bodyLower := strings.ToLower(body)

	// High-value keyword check
	highValueKeywords := []string{"login", "sign in", "signin", "password", "username"}
	keywordCount := 0
	for _, keyword := range highValueKeywords {
		if strings.Contains(bodyLower, keyword) {
			keywordCount++
		}
	}

	// Fast path: 2+ keywords = login page
	if keywordCount >= 2 {
		return true
	}

	// Check for control panels (high confidence)
	for _, signatures := range controlPanelSignatures {
		for _, signature := range signatures {
			if strings.Contains(bodyLower, signature) && keywordCount >= 1 {
				return true
			}
		}
	}

	// Password field + 1 keyword = login page
	if passwordFieldRegex.MatchString(body) && keywordCount >= 1 {
		return true
	}

	return false
}

// hasLoginForm checks if the response contains a login form using regex patterns
func (s *Scanner) hasLoginForm(body string) bool {
	// Must have a form element
	if !formTagRegex.MatchString(body) {
		return false
	}

	// Must have password field (using regex for better detection)
	if !passwordFieldRegex.MatchString(body) {
		return false
	}

	// Must have username/email field (using regex)
	if !usernameFieldRegex.MatchString(body) {
		return false
	}

	return true
}

// detectControlPanel checks if the response is from a known control panel
func (s *Scanner) detectControlPanel(body, urlStr string) (bool, string) {
	bodyLower := strings.ToLower(body)
	urlLower := strings.ToLower(urlStr)

	// Check each control panel signature
	for panelName, signatures := range controlPanelSignatures {
		// Check URL first (fast check)
		if strings.Contains(urlLower, panelName) {
			return true, panelName
		}
		
		// Check body signatures
		for _, signature := range signatures {
			if strings.Contains(bodyLower, signature) {
				return true, panelName
			}
		}
	}

	// Check for control panel ports
	for panelName, ports := range controlPanelPorts {
		for _, port := range ports {
			if strings.Contains(urlLower, ":"+port) {
				// Verify it has login indicators
				if strings.Contains(bodyLower, "login") || strings.Contains(bodyLower, "password") {
					return true, panelName
				}
			}
		}
	}

	return false, ""
}

// calculateConfidenceScore calculates a confidence score (0-100) for login page detection
func (s *Scanner) calculateConfidenceScore(result *EndpointResult) float64 {
	score := 0.0
	bodyLower := strings.ToLower(result.ResponseBody)
	urlLower := strings.ToLower(result.URL)

	// Check for control panel detection (high value bonus)
	isControlPanel, panelType := s.detectControlPanel(result.ResponseBody, result.URL)
	if isControlPanel {
		score += 30.0 // Strong bonus for control panels
		if panelType != "" {
			score += 5.0 // Extra for specific panel
		}
	}

	// URL-based scoring (max 25 points)
	if strings.Contains(urlLower, "/login") || strings.Contains(urlLower, "/signin") {
		score += 15.0
	} else if strings.Contains(urlLower, "/auth") || strings.Contains(urlLower, "cpanel") || strings.Contains(urlLower, "admin") {
		score += 10.0
	}

	// Check for control panel ports (bonus)
	for _, ports := range controlPanelPorts {
		for _, port := range ports {
			if strings.Contains(urlLower, ":"+port) {
				score += 10.0
				goto portFound // Exit nested loops
			}
		}
	}
portFound:

	// File extension bonus
	if strings.HasSuffix(urlLower, ".php") || strings.HasSuffix(urlLower, ".jsp") || 
	   strings.HasSuffix(urlLower, ".aspx") || strings.HasSuffix(urlLower, ".cgi") {
		score += 5.0
	}

	// Form detection (max 40 points)
	if result.HasLoginForm {
		score += 40.0
	} else if passwordFieldRegex.MatchString(result.ResponseBody) {
		score += 20.0 // Has password field but not complete form
	}

	// Content-based scoring (max 30 points)
	keywordCount := 0
	highValueKeywords := []string{"login", "sign in", "signin", "password", "username", "email"}
	for _, keyword := range highValueKeywords {
		if strings.Contains(bodyLower, keyword) {
			keywordCount++
		}
	}
	score += float64(keywordCount) * 3.0 // Up to 18 points for keywords

	if loginButtonRegex.MatchString(result.ResponseBody) {
		score += 12.0
	}

	// Status code adjustment
	if result.StatusCode >= 200 && result.StatusCode < 300 {
		score += 0.0 // No penalty for 2xx
	} else if result.StatusCode >= 300 && result.StatusCode < 400 {
		score -= 10.0 // Penalty for redirects
	}

	// Penalties for error indicators
	if result.IsError {
		score -= 50.0
	}
	if result.Is404 {
		score -= 50.0
	}

	// Ensure score is within 0-100 range
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// GetStats returns scanning statistics
func (s *Scanner) GetStats() (discovered, validated int) {
	return int(atomic.LoadInt32(&s.discovered)), int(atomic.LoadInt32(&s.validated))
}

// detectLanguage detects the language/framework from URL, headers, and response body
func (s *Scanner) detectLanguage(body, urlStr string, headers http.Header) string {
	bodyLower := strings.ToLower(body)
	urlLower := strings.ToLower(urlStr)
	
	// Check URL extension first
	if strings.Contains(urlLower, ".php") {
		return "php"
	}
	if strings.Contains(urlLower, ".jsp") || strings.Contains(urlLower, ".do") || strings.Contains(urlLower, ".action") {
		return "java"
	}
	if strings.Contains(urlLower, ".aspx") || strings.Contains(urlLower, ".asp") {
		return "dotnet"
	}
	if strings.Contains(urlLower, ".py") {
		return "python"
	}
	
	// Check HTTP headers
	server := strings.ToLower(headers.Get("Server"))
	xPoweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	
	if strings.Contains(xPoweredBy, "php") || strings.Contains(server, "php") {
		return "php"
	}
	if strings.Contains(xPoweredBy, "asp.net") || strings.Contains(server, "microsoft-iis") {
		return "dotnet"
	}
	if strings.Contains(server, "apache tomcat") || strings.Contains(server, "jboss") || strings.Contains(server, "weblogic") {
		return "java"
	}
	
	// Check response body for framework signatures
	// Next.js / React
	if strings.Contains(bodyLower, "__next") || strings.Contains(bodyLower, "_next/static") {
		return "nextjs"
	}
	if strings.Contains(bodyLower, "react") && (strings.Contains(bodyLower, "reactdom") || strings.Contains(bodyLower, "react-dom")) {
		return "react"
	}
	
	// Vue.js
	if strings.Contains(bodyLower, "vue.js") || strings.Contains(bodyLower, "vuejs") || strings.Contains(bodyLower, "data-v-") {
		return "vue"
	}
	
	// Nuxt.js
	if strings.Contains(bodyLower, "__nuxt") || strings.Contains(bodyLower, "_nuxt/") {
		return "nuxtjs"
	}
	
	// Angular
	if strings.Contains(bodyLower, "ng-version") || strings.Contains(bodyLower, "angular") {
		return "angular"
	}
	
	// Node.js/Express indicators
	if strings.Contains(xPoweredBy, "express") {
		return "node"
	}
	
	// WordPress
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		return "php"
	}
	
	// Laravel
	if strings.Contains(bodyLower, "laravel") || strings.Contains(bodyLower, "csrf-token") {
		return "php"
	}
	
	// Django
	if strings.Contains(bodyLower, "csrfmiddlewaretoken") || strings.Contains(bodyLower, "django") {
		return "python"
	}
	
	// Flask
	if strings.Contains(bodyLower, "flask") {
		return "python"
	}
	
	// Ruby on Rails
	if strings.Contains(bodyLower, "csrf-param") && strings.Contains(bodyLower, "csrf-token") {
		return "ruby"
	}
	
	// Spring Boot
	if strings.Contains(bodyLower, "spring") || strings.Contains(bodyLower, "whitelabel error page") {
		return "java"
	}
	
	return "unknown"
}

// isSSRFramework checks if the detected language is a server-side rendering framework
func (s *Scanner) isSSRFramework(language, body string) bool {
	ssrFrameworks := []string{"nextjs", "nuxtjs", "angular"}
	for _, framework := range ssrFrameworks {
		if strings.EqualFold(language, framework) {
			return true
		}
	}
	
	// Additional check for SSR indicators in body
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "server-side") || strings.Contains(bodyLower, "ssr") {
		return true
	}
	
	return false
}

// is404Page detects if a page is actually a 404 even if it returns 200 OK (common in SSR apps)
func (s *Scanner) is404Page(body string, statusCode int, isSSR bool) bool {
	// If status code is already 404, it's definitely a 404
	if statusCode == 404 {
		return true
	}
	
	// For SSR frameworks, check content for 404 indicators
	if isSSR || statusCode == 200 {
		bodyLower := strings.ToLower(body)
		
		// Common 404 page indicators
		fourZeroFourIndicators := []string{
			"404",
			"not found",
			"page not found",
			"page could not be found",
			"this page could not be found",
			"the page you are looking for",
			"the requested url was not found",
			"error 404",
			"http 404",
			"404 error",
			"does not exist",
			"could not be found",
			"page doesn't exist",
			"page does not exist",
		}
		
		// Count how many indicators we find
		indicatorCount := 0
		for _, indicator := range fourZeroFourIndicators {
			if strings.Contains(bodyLower, indicator) {
				indicatorCount++
			}
		}
		
		// If we find 2 or more indicators, it's likely a 404 page
		if indicatorCount >= 2 {
			return true
		}
		
		// Check for specific Next.js 404 page
		if strings.Contains(bodyLower, "this page could not be found") {
			return true
		}
		
		// Check for title containing 404
		if strings.Contains(bodyLower, "<title>") && strings.Contains(bodyLower, "404") {
			// Make sure "404" appears near the title tag
			titleStart := strings.Index(bodyLower, "<title>")
			if titleStart >= 0 {
				titleEnd := strings.Index(bodyLower[titleStart:], "</title>")
				if titleEnd > 0 && titleEnd < 100 { // Title should be reasonably short
					titleContent := bodyLower[titleStart : titleStart+titleEnd]
					if strings.Contains(titleContent, "404") {
						return true
					}
				}
			}
		}
	}
	
	return false
}

// detectError detects if an endpoint returned an error response
func (s *Scanner) detectError(body string, statusCode int, urlStr string) (bool, string) {
	bodyLower := strings.ToLower(body)
	
	// Check HTTP status codes for obvious errors
	if statusCode == 400 {
		return true, "400"
	}
	if statusCode == 401 {
		return true, "401"
	}
	if statusCode == 403 {
		return true, "403"
	}
	if statusCode == 404 {
		return true, "404"
	}
	if statusCode >= 500 && statusCode < 600 {
		return true, "500"
	}
	
	// Check for generic error pages
	errorIndicators := []string{
		"error",
		"exception",
		"not found",
		"access denied",
		"forbidden",
		"unauthorized",
		"bad request",
		"internal server error",
		"service unavailable",
		"gateway timeout",
	}
	
	// Check for framework-specific error pages
	frameworkErrors := map[string][]string{
		"nextjs": {
			"application error",
			"this page could not be found",
			"404 | this page could not be found",
		},
		"nuxtjs": {
			"an error occurred",
			"page not found",
			"this page could not be found",
		},
		"angular": {
			"error",
			"page not found",
		},
		"laravel": {
			"whoops",
			"something went wrong",
			"404 | not found",
			"403 | forbidden",
			"419 | page expired",
			"500 | server error",
			"503 | service unavailable",
		},
		"django": {
			"page not found",
			"server error",
			"404 not found",
			"500 internal server error",
		},
		"flask": {
			"404 not found",
			"internal server error",
			"method not allowed",
		},
		"spring": {
			"whitelabel error page",
			"there was an unexpected error",
			"http status",
		},
		"rails": {
			"we're sorry, but something went wrong",
			"the page you were looking for doesn't exist",
			"routing error",
		},
		"express": {
			"cannot get",
			"cannot post",
			"not found",
		},
	}
	
	// Check for framework-specific errors
	for _, errors := range frameworkErrors {
		for _, errPattern := range errors {
			if strings.Contains(bodyLower, errPattern) {
				return true, "invalid"
			}
		}
	}
	
	// Count generic error indicators
	errorCount := 0
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, indicator) {
			errorCount++
		}
	}
	
	// If body has multiple error indicators and no login indicators, it's likely an error page
	if errorCount >= 2 {
		// Double check it's not a login page with error message (like "invalid username")
		hasLoginIndicators := false
		for _, keyword := range loginKeywords {
			if strings.Contains(bodyLower, strings.ToLower(keyword)) {
				hasLoginIndicators = true
				break
			}
		}
		
		if !hasLoginIndicators {
			return true, "error"
		}
	}
	
	// Check for empty or minimal responses (might indicate invalid endpoint)
	if len(strings.TrimSpace(body)) < 50 && statusCode == 200 {
		// Very short response with 200 status - might be invalid
		// Unless it's an API endpoint that returns JSON
		if !strings.Contains(bodyLower, "{") && !strings.Contains(bodyLower, "[") {
			return true, "empty"
		}
	}
	
	// Check for redirect loops or infinite redirects
	if strings.Contains(bodyLower, "redirect") && strings.Contains(bodyLower, "too many") {
		return true, "redirect"
	}
	
	// Check for maintenance pages
	maintenanceIndicators := []string{
		"under maintenance",
		"maintenance mode",
		"temporarily unavailable",
		"be back soon",
		"coming soon",
	}
	
	for _, indicator := range maintenanceIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true, "maintenance"
		}
	}
	
	// Check for blocked/banned indicators
	blockedIndicators := []string{
		"blocked",
		"banned",
		"access denied",
		"rate limit",
		"too many requests",
		"captcha",
	}
	
	blockCount := 0
	for _, indicator := range blockedIndicators {
		if strings.Contains(bodyLower, indicator) {
			blockCount++
		}
	}
	
	if blockCount >= 2 {
		return true, "blocked"
	}
	
	// Check for default server pages (Apache, Nginx, IIS)
	defaultPages := []string{
		"apache2 ubuntu default page",
		"welcome to nginx",
		"iis windows server",
		"it works!",
		"test page",
		"default web site page",
	}
	
	for _, defaultPage := range defaultPages {
		if strings.Contains(bodyLower, defaultPage) {
			return true, "default"
		}
	}
	
	// Check title tag for error indicators
	if strings.Contains(bodyLower, "<title>") {
		titleStart := strings.Index(bodyLower, "<title>")
		if titleStart >= 0 {
			titleEnd := strings.Index(bodyLower[titleStart:], "</title>")
			if titleEnd > 0 && titleEnd < 200 {
				titleContent := bodyLower[titleStart : titleStart+titleEnd]
				
				// Check for error status codes in title
				errorCodes := []string{"400", "401", "403", "404", "500", "502", "503"}
				for _, code := range errorCodes {
					if strings.Contains(titleContent, code) {
						return true, code
					}
				}
				
				// Check for error words in title
				if strings.Contains(titleContent, "error") || 
				   strings.Contains(titleContent, "not found") ||
				   strings.Contains(titleContent, "forbidden") ||
				   strings.Contains(titleContent, "denied") {
					return true, "error"
				}
			}
		}
	}
	
	// No error detected
	return false, ""
}
