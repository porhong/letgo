package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProgressCallback is called with progress updates (scanned, total, percentage)
type ProgressCallback func(scanned, total int, percentage float64)

// ScannerConfig holds configuration for endpoint scanning
type ScannerConfig struct {
	BaseURL       string
	MaxThreads    int
	Timeout       time.Duration
	UserAgent     string
	CustomHeaders map[string]string
	OnProgress    ProgressCallback // Optional callback for progress updates
}

// EndpointResult represents a discovered endpoint
type EndpointResult struct {
	URL           string
	Method        string
	StatusCode    int
	IsLoginPage   bool
	HasLoginForm  bool
	ResponseBody  string
	ContentType   string
	ContentLength int
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

// Common login/auth endpoint patterns
var commonEndpoints = []string{
	// Basic login patterns
	"/login",
	"/signin",
	"/sign-in",
	"/sign_in",
	"/log-in",
	"/log_in",
	"/auth",
	"/authenticate",
	"/authentication",
	"/authorize",
	"/authorization",

	// Account/User login patterns
	"/account/login",
	"/account/signin",
	"/account/auth",
	"/user/login",
	"/user/signin",
	"/user/auth",
	"/users/login",
	"/users/signin",
	"/member/login",
	"/members/login",
	"/customer/login",
	"/customers/login",

	// Admin login patterns
	"/admin",
	"/admin/login",
	"/admin/signin",
	"/admin/auth",
	"/admin/authenticate",
	"/administrator",
	"/administrator/login",
	"/administrator/signin",
	"/adm",
	"/adm/login",
	"/management",
	"/management/login",
	"/manager",
	"/manager/login",

	// WordPress
	"/wp-login.php",
	"/wp-admin",
	"/wp-admin/login.php",
	"/wordpress/wp-login.php",
	"/blog/wp-login.php",
	"/wp/wp-login.php",

	// Drupal
	"/user/login",
	"/user",
	"/?q=user/login",

	// Joomla
	"/administrator",
	"/administrator/index.php",
	"/index.php/administrator",

	// Magento
	"/admin",
	"/admin/index",
	"/customer/account/login",

	// Laravel
	"/login",
	"/admin/login",
	"/auth/login",

	// Django
	"/accounts/login",
	"/admin/login",
	"/login/",

	// Rails
	"/users/sign_in",
	"/users/sign_in",
	"/admin/login",

	// Spring Boot
	"/login",
	"/auth/login",
	"/api/auth/login",

	// Dashboard/Portal patterns
	"/dashboard",
	"/dashboard/login",
	"/dashboard/signin",
	"/dashboard/auth",
	"/portal",
	"/portal/login",
	"/portal/signin",
	"/portal/auth",
	"/console",
	"/console/login",
	"/console/signin",
	"/console/auth",
	"/panel",
	"/panel/login",
	"/panel/signin",
	"/panel/auth",
	"/control",
	"/control/login",
	"/control-panel",
	"/control-panel/login",

	// API endpoints
	"/api/login",
	"/api/auth",
	"/api/authenticate",
	"/api/authorize",
	"/api/signin",
	"/api/v1/login",
	"/api/v1/auth",
	"/api/v1/authenticate",
	"/api/v1/authorize",
	"/api/v1/signin",
	"/api/v2/login",
	"/api/v2/auth",
	"/api/v2/authenticate",
	"/api/v2/authorize",
	"/api/v2/signin",
	"/api/v3/login",
	"/api/v3/auth",
	"/api/v3/authenticate",
	"/rest/api/login",
	"/rest/api/auth",
	"/rest/v1/login",
	"/rest/v1/auth",
	"/rest/v2/login",
	"/rest/v2/auth",

	// OAuth/OAuth2 patterns
	"/oauth",
	"/oauth/authorize",
	"/oauth/token",
	"/oauth/login",
	"/oauth/auth",
	"/oauth2",
	"/oauth2/authorize",
	"/oauth2/token",
	"/oauth2/login",
	"/oauth2/auth",
	"/oauth2/v2/authorize",
	"/oauth2/v2/token",

	// SSO patterns
	"/sso",
	"/sso/login",
	"/sso/signin",
	"/sso/auth",
	"/sso/authenticate",
	"/saml/login",
	"/saml/sso",
	"/saml2/login",
	"/saml2/sso",
	"/cas/login",
	"/cas/authenticate",

	// Application/Web patterns
	"/app",
	"/app/login",
	"/app/signin",
	"/app/auth",
	"/web",
	"/web/login",
	"/web/signin",
	"/web/auth",
	"/service",
	"/service/login",
	"/service/signin",
	"/service/auth",
	"/secure",
	"/secure/login",
	"/secure/signin",
	"/secure/auth",
	"/system",
	"/system/login",
	"/system/signin",
	"/system/auth",
	"/site",
	"/site/login",
	"/site/signin",
	"/site/auth",
	"/main",
	"/main/login",
	"/main/signin",

	// Versioned endpoints
	"/v1/login",
	"/v1/auth",
	"/v1/authenticate",
	"/v1/signin",
	"/v2/login",
	"/v2/auth",
	"/v2/authenticate",
	"/v2/signin",
	"/v3/login",
	"/v3/auth",
	"/v3/authenticate",
	"/v3/signin",

	// File extension patterns
	"/login.php",
	"/login.html",
	"/login.jsp",
	"/login.aspx",
	"/login.cfm",
	"/login.do",
	"/login.action",
	"/signin.php",
	"/signin.html",
	"/signin.jsp",
	"/signin.aspx",
	"/auth.php",
	"/auth.html",
	"/auth.jsp",
	"/auth.aspx",
	"/authenticate.php",
	"/authenticate.html",
	"/authenticate.jsp",

	// Index-based patterns
	"/index.php/login",
	"/index.html/login",
	"/index.jsp/login",
	"/index.aspx/login",
	"/index.php/auth",
	"/index.html/auth",
	"/index.jsp/auth",

	// Control panels
	"/cpanel",
	"/cpanel/login",
	"/whm",
	"/whm/login",
	"/plesk",
	"/plesk/login",
	"/directadmin",
	"/directadmin/login",
	"/webmin",
	"/webmin/login",

	// Database admin panels
	"/phpmyadmin",
	"/phpMyAdmin",
	"/pma",
	"/mysql",
	"/mysql/login",
	"/adminer",
	"/adminer.php",
	"/dbadmin",
	"/db-admin",

	// Application servers
	"/manager",
	"/manager/html",
	"/manager/html/login",
	"/tomcat/manager",
	"/tomcat/manager/html",
	"/tomcat/manager/html/login",
	"/jboss",
	"/jboss/login",
	"/weblogic",
	"/weblogic/login",
	"/websphere",
	"/websphere/login",

	// CI/CD and DevOps tools
	"/jenkins",
	"/jenkins/login",
	"/jenkins/j_acegi_security_check",
	"/gitlab",
	"/gitlab/users/sign_in",
	"/gitlab/login",
	"/bitbucket",
	"/bitbucket/login",
	"/jira",
	"/jira/login",
	"/confluence",
	"/confluence/login",
	"/sonarqube",
	"/sonarqube/login",
	"/nexus",
	"/nexus/login",
	"/artifactory",
	"/artifactory/login",

	// Monitoring and analytics
	"/grafana",
	"/grafana/login",
	"/kibana",
	"/kibana/login",
	"/elastic",
	"/elastic/login",
	"/prometheus",
	"/prometheus/login",
	"/zabbix",
	"/zabbix/login",
	"/nagios",
	"/nagios/login",
	"/cacti",
	"/cacti/login",

	// Cloud services
	"/aws",
	"/aws/login",
	"/azure",
	"/azure/login",
	"/gcp",
	"/gcp/login",
	"/cloud",
	"/cloud/login",

	// Enterprise software
	"/sharepoint",
	"/sharepoint/login",
	"/exchange",
	"/exchange/login",
	"/owa",
	"/owa/auth/logon.aspx",
	"/citrix",
	"/citrix/login",
	"/vmware",
	"/vmware/login",
	"/vcenter",
	"/vcenter/login",

	// Development tools
	"/phpinfo.php",
	"/info.php",
	"/test.php",
	"/debug",
	"/debug/login",

	// Mobile/API specific
	"/mobile/login",
	"/mobile/auth",
	"/mobile/api/login",
	"/app/api/login",
	"/app/api/auth",

	// Additional variations
	"/sign-up",
	"/signup",
	"/register",
	"/registration",
	"/join",
	"/enter",
	"/access",
	"/entry",
	"/gateway",
	"/gateway/login",
	"/hub",
	"/hub/login",
	"/center",
	"/center/login",
	"/home/login",
	"/welcome/login",
	"/start/login",
	"/begin/login",

	// International variations
	"/connexion",
	"/anmelden",
	"/acceder",
	"/entrar",
	"/ingresar",
	"/acesso",
	"/prijava",
	"/giriş",
	"/ログイン",
	"/登录",
	"/登入",
}

// Common subdomain patterns for scanning
var commonSubdomains = []string{
	"www",
	"admin",
	"administrator",
	"adm",
	"cpanel",
	"cp",
	"panel",
	"control",
	"dashboard",
	"portal",
	"login",
	"auth",
	"authenticate",
	"signin",
	"api",
	"api1",
	"api2",
	"v1",
	"v2",
	"v3",
	"secure",
	"secure1",
	"secure2",
	"ssl",
	"mail",
	"email",
	"webmail",
	"owa",
	"exchange",
	"sharepoint",
	"dev",
	"development",
	"test",
	"testing",
	"staging",
	"stage",
	"prod",
	"production",
	"app",
	"apps",
	"application",
	"web",
	"www2",
	"www3",
	"blog",
	"blogs",
	"forum",
	"forums",
	"shop",
	"store",
	"ecommerce",
	"payment",
	"payments",
	"billing",
	"account",
	"accounts",
	"user",
	"users",
	"member",
	"members",
	"customer",
	"customers",
	"client",
	"clients",
	"support",
	"help",
	"docs",
	"documentation",
	"wiki",
	"kb",
	"knowledgebase",
	"status",
	"monitor",
	"monitoring",
	"grafana",
	"kibana",
	"jenkins",
	"gitlab",
	"bitbucket",
	"jira",
	"confluence",
	"sonarqube",
	"nexus",
	"artifactory",
	"phpmyadmin",
	"pma",
	"mysql",
	"db",
	"database",
	"redis",
	"elastic",
	"elasticsearch",
	"prometheus",
	"zabbix",
	"nagios",
	"cacti",
	"vmware",
	"vcenter",
	"citrix",
	"aws",
	"azure",
	"gcp",
	"cloud",
	"cdn",
	"static",
	"assets",
	"media",
	"images",
	"img",
	"files",
	"file",
	"upload",
	"download",
	"downloads",
	"ftp",
	"sftp",
	"smtp",
	"imap",
	"pop",
	"pop3",
	"ldap",
	"ad",
	"active-directory",
	"adfs",
	"okta",
	"auth0",
	"sso",
	"saml",
	"oauth",
	"oauth2",
	"m",
	"mobile",
	"mob",
	"wap",
	"i",
	"iphone",
	"android",
	"ios",
	"old",
	"new",
	"backup",
	"backups",
	"archive",
	"archives",
	"legacy",
	"beta",
	"alpha",
	"demo",
	"demos",
	"sample",
	"samples",
	"example",
	"examples",
	"internal",
	"intranet",
	"extranet",
	"vpn",
	"remote",
	"access",
	"gateway",
	"proxy",
	"cache",
	"cdn1",
	"cdn2",
	"edge",
	"origin",
	"origin1",
	"origin2",
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
	port := baseURL.Port()
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

	// Build host with port if needed
	buildHost := func(subdomain string) string {
		if subdomain != "" {
			hostWithSub := subdomain + "." + baseDomain
			if port != "" {
				return hostWithSub + ":" + port
			}
			return hostWithSub
		}
		if port != "" {
			return host + ":" + port
		}
		return host
	}

	// Generate all URLs to scan (base domain + subdomains)
	endpoints := make([]string, 0)

	// First, scan base domain and common subdomains
	domainsToScan := []string{""} // Empty string means base domain
	domainsToScan = append(domainsToScan, commonSubdomains...)

	for _, subdomain := range domainsToScan {
		scanHost := buildHost(subdomain)
		scanURL := &url.URL{
			Scheme: scheme,
			Host:   scanHost,
			Path:   "/",
		}

		// Generate endpoint URLs for this domain
		for _, endpoint := range commonEndpoints {
			fullURL := scanURL.ResolveReference(&url.URL{Path: strings.TrimPrefix(endpoint, "/")}).String()
			endpoints = append(endpoints, fullURL)
		}

		// Also scan the root of this domain
		endpoints = append(endpoints, scanURL.String())
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
	validResults := make([]EndpointResult, 0)
	seenURLs := make(map[string]bool) // Avoid duplicates

	for result := range results {
		// Skip if we've already seen this URL
		if seenURLs[result.URL] {
			continue
		}
		seenURLs[result.URL] = true

		// Include if it has login form/page detection
		if result.IsLoginPage || result.HasLoginForm {
			validResults = append(validResults, result)
			continue
		}

		// Also include if it returns valid status code (2xx, 3xx) and is from a known login path
		// This catches API endpoints and pages that might not have detectable forms
		if result.StatusCode >= 200 && result.StatusCode < 400 {
			// Check if URL path contains common login keywords
			resultURL, err := url.Parse(result.URL)
			if err == nil {
				pathLower := strings.ToLower(resultURL.Path)
				loginPathKeywords := []string{
					"login", "signin", "auth", "authenticate", "admin", "administrator",
					"oauth", "sso", "saml", "portal", "dashboard", "console", "panel",
				}
				for _, keyword := range loginPathKeywords {
					if strings.Contains(pathLower, keyword) {
						validResults = append(validResults, result)
						break
					}
				}
			}
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

	// Analyze if this is a login page
	result.IsLoginPage = s.isLoginPage(result.ResponseBody, result.StatusCode)
	result.HasLoginForm = s.hasLoginForm(result.ResponseBody)

	return result
}

// isLoginPage checks if the response indicates a login page
func (s *Scanner) isLoginPage(body string, statusCode int) bool {
	bodyLower := strings.ToLower(body)

	// Check status code (2xx or 3xx are usually valid)
	if statusCode < 200 || statusCode >= 400 {
		return false
	}

	// Check for login-related keywords
	keywordCount := 0
	for _, keyword := range loginKeywords {
		if strings.Contains(bodyLower, strings.ToLower(keyword)) {
			keywordCount++
		}
	}

	// If we find at least one login keyword, it's likely a login page
	// (reduced from 2 to 1 to be less strict)
	if keywordCount >= 1 {
		return true
	}

	// Check for common login form indicators
	formIndicators := []string{
		"<form", "type=\"password\"", "type='password'",
		"input type=\"password\"", "input type='password'",
		"login-form", "loginform", "signin-form", "signinform",
	}

	for _, indicator := range formIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}

	return false
}

// hasLoginForm checks if the response contains a login form
func (s *Scanner) hasLoginForm(body string) bool {
	bodyLower := strings.ToLower(body)

	// Must have a form element
	if !strings.Contains(bodyLower, "<form") {
		return false
	}

	// Must have password field
	if !strings.Contains(bodyLower, "type=\"password\"") && !strings.Contains(bodyLower, "type='password'") {
		return false
	}

	// Check for username/email field
	hasUsernameField := false
	for _, field := range loginFormFields {
		if strings.Contains(bodyLower, "name=\""+field+"\"") || strings.Contains(bodyLower, "name='"+field+"'") {
			hasUsernameField = true
			break
		}
	}

	return hasUsernameField
}

// GetStats returns scanning statistics
func (s *Scanner) GetStats() (discovered, validated int) {
	return int(atomic.LoadInt32(&s.discovered)), int(atomic.LoadInt32(&s.validated))
}
