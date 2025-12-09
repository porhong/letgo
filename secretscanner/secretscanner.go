package secretscanner

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

// ScanResult represents a found sensitive data item
type ScanResult struct {
	URL         string
	Type        string // "env", "token", "config", "api_key", "credential"
	Severity    string // "high", "medium", "low"
	Pattern     string // The pattern that matched
	Value       string // The actual value found (may be truncated)
	Location    string // Where it was found: "body", "header", "file"
	FilePath    string // If found in a file path
	Description string // Human-readable description
}

// ScannerConfig holds configuration for secret scanning
type ScannerConfig struct {
	BaseURL         string
	MaxThreads      int
	Timeout         time.Duration
	UserAgent       string
	CustomHeaders   map[string]string
	FollowRedirects bool
	MaxDepth        int // Maximum depth for recursive scanning
}

// Scanner handles secret scanning
type Scanner struct {
	config  ScannerConfig
	results []ScanResult
	mu      sync.Mutex
	scanned int32
}

// Common sensitive file paths to check
var sensitiveFilePaths = []string{
	// Environment files
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.development",
	"/.env.test",
	"/.env.staging",
	"/env",
	"/environment",

	// Configuration files
	"/config.json",
	"/config.yml",
	"/config.yaml",
	"/config.xml",
	"/configuration.json",
	"/settings.json",
	"/appsettings.json",
	"/application.properties",
	"/application.yml",
	"/application.yaml",

	// Git files
	"/.git/config",
	"/.git/HEAD",
	"/.gitignore",

	// Backup files
	"/.env.backup",
	"/.env.old",
	"/config.json.bak",
	"/config.json.old",
	"/config.json.backup",

	// Common config directories
	"/config/config.json",
	"/config/config.yml",
	"/app/config.json",
	"/app/config.yml",
	"/src/config.json",
	"/src/config.yml",

	// Framework-specific
	"/wp-config.php",
	"/config/database.yml",
	"/config/secrets.yml",
	"/config/credentials.yml",

	// API and keys
	"/api-keys.json",
	"/secrets.json",
	"/credentials.json",
	"/keys.json",

	// Docker
	"/docker-compose.yml",
	"/docker-compose.yaml",
	"/Dockerfile",

	// CI/CD
	"/.github/workflows",
	"/.gitlab-ci.yml",
	"/.travis.yml",
	"/.circleci/config.yml",

	// Cloud provider configs
	"/.aws/credentials",
	"/.gcloud/credentials",
	"/.azure/credentials",
}

// Regex patterns for detecting sensitive data
var (
	// Environment variable patterns
	envVarPattern = regexp.MustCompile(`(?i)(?:^|\s|"|')(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*([^\s"']+|"[^"]*"|'[^']*')`)

	// API Key patterns
	apiKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`),
		regexp.MustCompile(`(?i)(?:api[_-]?token|apitoken)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`),
		regexp.MustCompile(`(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`),
		regexp.MustCompile(`(?i)(?:access[_-]?token|accesstoken)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`),
	}

	// JWT Token pattern
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)

	// AWS credentials
	awsKeyPattern    = regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id|aws_access_key_id)\s*[:=]\s*["']?([A-Z0-9]{20})["']?`)
	awsSecretPattern = regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws_secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`)

	// Database connection strings
	dbPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:mysql|postgresql|postgres|mongodb)://[^\s"']+`),
		regexp.MustCompile(`(?i)(?:database[_-]?url|db[_-]?url|connection[_-]?string)\s*[:=]\s*["']?([^\s"']+)["']?`),
		regexp.MustCompile(`(?i)(?:db[_-]?password|database[_-]?password)\s*[:=]\s*["']?([^\s"']+)["']?`),
	}

	// OAuth tokens
	oauthPattern = regexp.MustCompile(`(?i)(?:oauth[_-]?token|oauth_token)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`)

	// Private keys
	privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----`)

	// Email patterns (sometimes used in configs)
	emailPattern = regexp.MustCompile(`(?i)(?:email|mail|smtp[_-]?user)\s*[:=]\s*["']?([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})["']?`)

	// Password patterns
	passwordPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})["']?`),
		regexp.MustCompile(`(?i)(?:db[_-]?password|database[_-]?password)\s*[:=]\s*["']?([^\s"']+)["']?`),
	}

	// GitHub/GitLab tokens
	gitTokenPattern = regexp.MustCompile(`(?i)(?:github[_-]?token|gitlab[_-]?token|git[_-]?token)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`)

	// Slack tokens
	slackPattern = regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,}`)

	// Stripe keys
	stripePattern = regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}`)

	// PayPal tokens
	paypalPattern = regexp.MustCompile(`(?i)(?:paypal[_-]?client[_-]?id|paypal[_-]?secret)\s*[:=]\s*["']?([a-z0-9]{32,})["']?`)
)

// New creates a new scanner instance
func New(config ScannerConfig) *Scanner {
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	}
	if config.MaxThreads == 0 {
		config.MaxThreads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = 2
	}
	return &Scanner{
		config:  config,
		results: make([]ScanResult, 0),
	}
}

// Scan performs a comprehensive scan for sensitive data
func (s *Scanner) Scan(ctx context.Context) ([]ScanResult, error) {
	baseURL, err := url.Parse(s.config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Ensure scheme
	if baseURL.Scheme == "" {
		baseURL.Scheme = "https"
	}

	// Normalize URL
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	if baseURL.Path == "" {
		baseURL.Path = "/"
	}

	// Generate URLs to scan
	urlsToScan := make([]string, 0)

	// Add base URL
	urlsToScan = append(urlsToScan, baseURL.String())

	// Add sensitive file paths
	for _, path := range sensitiveFilePaths {
		scanURL := *baseURL
		scanURL.Path = path
		urlsToScan = append(urlsToScan, scanURL.String())
	}

	// Create channels for jobs and results
	jobs := make(chan string, len(urlsToScan))
	results := make(chan ScanResult, len(urlsToScan)*10) // Buffer for multiple findings per URL

	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < s.config.MaxThreads; i++ {
		wg.Add(1)
		go s.worker(ctx, i, jobs, results, &wg)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, urlStr := range urlsToScan {
			select {
			case <-ctx.Done():
				return
			case jobs <- urlStr:
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	allResults := make([]ScanResult, 0)
	seenResults := make(map[string]bool) // Deduplicate

	for result := range results {
		// Create a unique key for deduplication
		key := fmt.Sprintf("%s:%s:%s", result.URL, result.Type, result.Pattern)
		if !seenResults[key] {
			seenResults[key] = true
			allResults = append(allResults, result)
		}
	}

	s.mu.Lock()
	s.results = allResults
	s.mu.Unlock()

	return allResults, nil
}

// worker processes scanning jobs
func (s *Scanner) worker(ctx context.Context, id int, jobs <-chan string, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: s.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !s.config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	for urlStr := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			atomic.AddInt32(&s.scanned, 1)
			s.scanURL(client, urlStr, results)
		}
	}
}

// scanURL scans a single URL for sensitive data
func (s *Scanner) scanURL(client *http.Client, urlStr string, results chan<- ScanResult) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return
	}

	// Set headers
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// Add custom headers
	if s.config.CustomHeaders != nil {
		for key, value := range s.config.CustomHeaders {
			req.Header.Set(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Only scan successful responses (2xx, 3xx)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return
	}

	// Read response body (limit to 1MB for analysis)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return
	}

	body := string(bodyBytes)
	contentType := resp.Header.Get("Content-Type")

	// Check if this looks like a config file
	isConfigFile := s.isConfigFile(urlStr, contentType)

	// Scan body for patterns
	s.scanBody(body, urlStr, isConfigFile, results)

	// Scan headers for sensitive data
	s.scanHeaders(resp.Header, urlStr, results)
}

// scanBody scans response body for sensitive patterns
func (s *Scanner) scanBody(body, urlStr string, isConfigFile bool, results chan<- ScanResult) {
	// Scan for environment variables
	matches := envVarPattern.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			key := match[1]
			value := match[2]

			// Check if it's a sensitive key
			if s.isSensitiveKey(key) {
				severity := s.getSeverity(key, value)
				results <- ScanResult{
					URL:         urlStr,
					Type:        "env",
					Severity:    severity,
					Pattern:     key,
					Value:       s.truncateValue(value),
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: fmt.Sprintf("Environment variable found: %s", key),
				}
			}
		}
	}

	// Scan for JWT tokens
	jwtMatches := jwtPattern.FindAllString(body, -1)
	for _, match := range jwtMatches {
		results <- ScanResult{
			URL:         urlStr,
			Type:        "token",
			Severity:    "high",
			Pattern:     "JWT",
			Value:       s.truncateValue(match),
			Location:    "body",
			FilePath:    s.extractFilePath(urlStr),
			Description: "JWT token found",
		}
	}

	// Scan for API keys
	for _, pattern := range apiKeyPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				results <- ScanResult{
					URL:         urlStr,
					Type:        "api_key",
					Severity:    "high",
					Pattern:     pattern.String(),
					Value:       s.truncateValue(match[1]),
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: "API key found",
				}
			}
		}
	}

	// Scan for AWS credentials
	if awsKeyMatches := awsKeyPattern.FindAllStringSubmatch(body, -1); len(awsKeyMatches) > 0 {
		for _, match := range awsKeyMatches {
			if len(match) >= 2 {
				results <- ScanResult{
					URL:         urlStr,
					Type:        "credential",
					Severity:    "high",
					Pattern:     "AWS_ACCESS_KEY_ID",
					Value:       s.truncateValue(match[1]),
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: "AWS Access Key ID found",
				}
			}
		}
	}

	if awsSecretMatches := awsSecretPattern.FindAllStringSubmatch(body, -1); len(awsSecretMatches) > 0 {
		for _, match := range awsSecretMatches {
			if len(match) >= 2 {
				results <- ScanResult{
					URL:         urlStr,
					Type:        "credential",
					Severity:    "high",
					Pattern:     "AWS_SECRET_ACCESS_KEY",
					Value:       s.truncateValue(match[1]),
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: "AWS Secret Access Key found",
				}
			}
		}
	}

	// Scan for database connection strings
	for _, pattern := range dbPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 1 {
				results <- ScanResult{
					URL:         urlStr,
					Type:        "credential",
					Severity:    "high",
					Pattern:     "database_connection",
					Value:       s.truncateValue(match[0]),
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: "Database connection string found",
				}
			}
		}
	}

	// Scan for OAuth tokens
	oauthMatches := oauthPattern.FindAllStringSubmatch(body, -1)
	for _, match := range oauthMatches {
		if len(match) >= 2 {
			results <- ScanResult{
				URL:         urlStr,
				Type:        "token",
				Severity:    "high",
				Pattern:     "OAuth",
				Value:       s.truncateValue(match[1]),
				Location:    "body",
				FilePath:    s.extractFilePath(urlStr),
				Description: "OAuth token found",
			}
		}
	}

	// Scan for private keys
	privateKeyMatches := privateKeyPattern.FindAllString(body, -1)
	for _, match := range privateKeyMatches {
		results <- ScanResult{
			URL:         urlStr,
			Type:        "credential",
			Severity:    "high",
			Pattern:     "PRIVATE_KEY",
			Value:       s.truncateValue(match),
			Location:    "body",
			FilePath:    s.extractFilePath(urlStr),
			Description: "Private key found",
		}
	}

	// Scan for passwords
	for _, pattern := range passwordPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) >= 2 && len(match[1]) >= 8 {
				results <- ScanResult{
					URL:         urlStr,
					Type:        "credential",
					Severity:    "high",
					Pattern:     "password",
					Value:       "***REDACTED***",
					Location:    "body",
					FilePath:    s.extractFilePath(urlStr),
					Description: "Password found in configuration",
				}
			}
		}
	}

	// Scan for Git tokens
	gitMatches := gitTokenPattern.FindAllStringSubmatch(body, -1)
	for _, match := range gitMatches {
		if len(match) >= 2 {
			results <- ScanResult{
				URL:         urlStr,
				Type:        "token",
				Severity:    "high",
				Pattern:     "GIT_TOKEN",
				Value:       s.truncateValue(match[1]),
				Location:    "body",
				FilePath:    s.extractFilePath(urlStr),
				Description: "Git token found",
			}
		}
	}

	// Scan for Slack tokens
	slackMatches := slackPattern.FindAllString(body, -1)
	for _, match := range slackMatches {
		results <- ScanResult{
			URL:         urlStr,
			Type:        "token",
			Severity:    "medium",
			Pattern:     "SLACK_TOKEN",
			Value:       s.truncateValue(match),
			Location:    "body",
			FilePath:    s.extractFilePath(urlStr),
			Description: "Slack token found",
		}
	}

	// Scan for Stripe keys
	stripeMatches := stripePattern.FindAllString(body, -1)
	for _, match := range stripeMatches {
		results <- ScanResult{
			URL:         urlStr,
			Type:        "api_key",
			Severity:    "high",
			Pattern:     "STRIPE_KEY",
			Value:       s.truncateValue(match),
			Location:    "body",
			FilePath:    s.extractFilePath(urlStr),
			Description: "Stripe API key found",
		}
	}

	// If this is a config file, mark it
	if isConfigFile {
		results <- ScanResult{
			URL:         urlStr,
			Type:        "config",
			Severity:    "medium",
			Pattern:     "config_file",
			Value:       "",
			Location:    "file",
			FilePath:    s.extractFilePath(urlStr),
			Description: "Configuration file is publicly accessible",
		}
	}
}

// scanHeaders scans HTTP headers for sensitive data
func (s *Scanner) scanHeaders(headers http.Header, urlStr string, results chan<- ScanResult) {
	// Check for sensitive headers
	sensitiveHeaders := []string{
		"X-API-Key",
		"X-Auth-Token",
		"Authorization",
		"X-Access-Token",
	}

	for _, headerName := range sensitiveHeaders {
		if value := headers.Get(headerName); value != "" {
			results <- ScanResult{
				URL:         urlStr,
				Type:        "token",
				Severity:    "medium",
				Pattern:     headerName,
				Value:       s.truncateValue(value),
				Location:    "header",
				FilePath:    s.extractFilePath(urlStr),
				Description: fmt.Sprintf("Sensitive header found: %s", headerName),
			}
		}
	}
}

// isSensitiveKey checks if an environment variable key is sensitive
func (s *Scanner) isSensitiveKey(key string) bool {
	keyLower := strings.ToLower(key)
	sensitiveKeywords := []string{
		"password", "passwd", "pwd", "secret", "key", "token", "auth",
		"api", "credential", "private", "access", "aws", "database", "db",
		"mysql", "postgres", "mongodb", "redis", "email", "mail", "smtp",
		"oauth", "jwt", "session", "cookie", "encryption", "encrypt",
		"ssl", "tls", "cert", "certificate", "ssh", "github", "gitlab",
		"stripe", "paypal", "slack", "discord", "telegram", "twilio",
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(keyLower, keyword) {
			return true
		}
	}
	return false
}

// getSeverity determines the severity of a finding
func (s *Scanner) getSeverity(key, value string) string {
	keyLower := strings.ToLower(key)

	// High severity keywords
	highSeverityKeywords := []string{
		"password", "secret", "private", "key", "token", "credential",
		"aws", "database", "db", "mysql", "postgres", "mongodb",
		"oauth", "jwt", "api", "access",
	}

	for _, keyword := range highSeverityKeywords {
		if strings.Contains(keyLower, keyword) {
			return "high"
		}
	}

	// Medium severity
	if len(value) > 20 {
		return "medium"
	}

	return "low"
}

// truncateValue truncates a value for display
func (s *Scanner) truncateValue(value string) string {
	if len(value) > 50 {
		return value[:47] + "..."
	}
	return value
}

// extractFilePath extracts the file path from URL
func (s *Scanner) extractFilePath(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Path
}

// isConfigFile checks if a URL/response looks like a config file
func (s *Scanner) isConfigFile(urlStr, contentType string) bool {
	urlLower := strings.ToLower(urlStr)
	contentTypeLower := strings.ToLower(contentType)

	// Check URL extension
	configExtensions := []string{".json", ".yml", ".yaml", ".xml", ".properties", ".env", ".config"}
	for _, ext := range configExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	// Check content type
	if strings.Contains(contentTypeLower, "json") ||
		strings.Contains(contentTypeLower, "yaml") ||
		strings.Contains(contentTypeLower, "xml") ||
		strings.Contains(contentTypeLower, "text/plain") {
		// Check if URL contains config-related keywords
		configKeywords := []string{"config", "setting", "env", "secret", "credential", "key"}
		for _, keyword := range configKeywords {
			if strings.Contains(urlLower, keyword) {
				return true
			}
		}
	}

	return false
}

// GetStats returns scanning statistics
func (s *Scanner) GetStats() int {
	return int(atomic.LoadInt32(&s.scanned))
}
