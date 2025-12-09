package cracker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type AttackConfig struct {
	Target       string
	Username     string
	Userlist     string            // Path to userlist file (optional, overrides Username if set)
	Wordlist     string
	MaxThreads   int
	Protocol     string
	Port         int
	Timeout      time.Duration
	ShowAttempts bool
	// Login endpoint specific fields
	Endpoint        string            // e.g., "/login", "/api/auth"
	Method          string            // "GET" or "POST", defaults to "GET" for basic auth, "POST" for login
	UsernameField   string            // Form field name for username (e.g., "username", "email")
	PasswordField   string            // Form field name for password (e.g., "password")
	ContentType     string            // "application/x-www-form-urlencoded" or "application/json"
	SuccessCodes    []int             // HTTP status codes that indicate success (e.g., [200, 302])
	SuccessKeywords []string          // Keywords in response body that indicate success
	FailureKeywords []string          // Keywords in response body that indicate failure
	CustomHeaders   map[string]string // Custom headers to send with requests
	FollowRedirects bool              // Whether to follow redirects (default: false)
}

type PasswordCracker struct {
	config     AttackConfig
	userlist   []string
	wordlist   []string
	stats      AttackStats
	cancelFunc context.CancelFunc
	mu         sync.Mutex
	attempts   int32 // Use atomic counter for thread safety
	total      int32 // Total combinations to try
	lastProgress int32 // Last reported progress percentage
}

type AttackStats struct {
	Attempts  int
	Found     bool
	Username  string
	Password  string
	StartTime time.Time
	EndTime   time.Time
}

func New(config AttackConfig) *PasswordCracker {
	return &PasswordCracker{
		config: config,
		stats: AttackStats{
			StartTime: time.Now(),
		},
	}
}

func (pc *PasswordCracker) LoadWordlist() error {
	file, err := os.Open(pc.config.Wordlist)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			pc.wordlist = append(pc.wordlist, password)
		}
	}

	return scanner.Err()
}

func (pc *PasswordCracker) LoadUserlist() error {
	// If Userlist is not set, use single Username
	if pc.config.Userlist == "" {
		if pc.config.Username != "" {
			pc.userlist = []string{pc.config.Username}
		}
		return nil
	}

	file, err := os.Open(pc.config.Userlist)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username != "" {
			pc.userlist = append(pc.userlist, username)
		}
	}

	return scanner.Err()
}

// CredentialPair represents a username/password combination
type CredentialPair struct {
	Username string
	Password string
}

func (pc *PasswordCracker) Start() (bool, string) {
	ctx, cancel := context.WithCancel(context.Background())
	pc.cancelFunc = cancel

	if len(pc.wordlist) == 0 {
		pc.stats.EndTime = time.Now()
		return false, ""
	}

	// If userlist is empty, use the single username from config
	if len(pc.userlist) == 0 {
		if pc.config.Username != "" {
			pc.userlist = []string{pc.config.Username}
		} else {
			pc.stats.EndTime = time.Now()
			return false, ""
		}
	}

	// Calculate total combinations
	totalCombinations := len(pc.userlist) * len(pc.wordlist)
	pc.total = int32(totalCombinations)
	jobs := make(chan CredentialPair, totalCombinations)
	results := make(chan CredentialPair, 1) // Only need capacity for 1 result

	var wg sync.WaitGroup

	// Start progress tracker
	progressCtx, progressCancel := context.WithCancel(ctx)
	defer progressCancel()
	go pc.trackProgress(progressCtx)

	// Start workers
	for i := 0; i < pc.config.MaxThreads; i++ {
		wg.Add(1)
		go pc.workerMultiUser(ctx, i, jobs, results, &wg)
	}

	// Send jobs (all username/password combinations)
	go func() {
		defer close(jobs)
		for _, username := range pc.userlist {
			for _, password := range pc.wordlist {
				select {
				case <-ctx.Done():
					return
				case jobs <- CredentialPair{Username: username, Password: password}:
				}
			}
		}
	}()

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	for result := range results {
		if result.Password != "" {
			pc.stats.Found = true
			pc.stats.Username = result.Username
			pc.stats.Password = result.Password
			cancel() // Cancel context to stop all workers
			pc.stats.EndTime = time.Now()
			pc.stats.Attempts = int(pc.attempts)
			fmt.Println() // New line after progress bar
			return true, result.Username + ":" + result.Password
		}
	}

	pc.stats.EndTime = time.Now()
	pc.stats.Attempts = int(pc.attempts)
	fmt.Println() // New line after progress bar
	return false, ""
}

// workerMultiUser handles credential pairs (username/password combinations)
func (pc *PasswordCracker) workerMultiUser(ctx context.Context, id int, jobs <-chan CredentialPair, results chan<- CredentialPair, wg *sync.WaitGroup) {
	defer wg.Done()

	for cred := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Safely increment attempts counter
			attemptNum := atomic.AddInt32(&pc.attempts, 1)

			if pc.config.ShowAttempts {
				// Use log for thread-safe output
				log.Printf("[Thread %d] Attempt %d: %s:%s\n", id, attemptNum, cred.Username, cred.Password)
			}

			success := false

			switch pc.config.Protocol {
			case "http", "https":
				if pc.config.Method == "POST" || pc.config.Endpoint != "" {
					success = pc.testHTTPLoginWithUser(cred.Username, cred.Password)
				} else {
					success = pc.testHTTPWithUser(cred.Username, cred.Password)
				}
			case "ssh":
				success = pc.testSSHWithUser(cred.Username, cred.Password)
			case "hash":
				success = pc.testHash(cred.Password, pc.config.Target)
			default:
				log.Printf("Unsupported protocol: %s", pc.config.Protocol)
			}

			if success {
				select {
				case results <- cred:
					return
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (pc *PasswordCracker) worker(ctx context.Context, id int, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for password := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Safely increment attempts counter
			attemptNum := atomic.AddInt32(&pc.attempts, 1)

			if pc.config.ShowAttempts {
				// Use log for thread-safe output
				log.Printf("[Thread %d] Attempt %d: %s\n", id, attemptNum, password)
			}

			success := false

			switch pc.config.Protocol {
			case "http", "https":
				if pc.config.Method == "POST" || pc.config.Endpoint != "" {
					success = pc.testHTTPLogin(password)
				} else {
					success = pc.testHTTP(password)
				}
			case "ssh":
				success = pc.testSSH(password)
			case "hash":
				success = pc.testHash(password, pc.config.Target)
			default:
				log.Printf("Unsupported protocol: %s", pc.config.Protocol)
			}

			if success {
				select {
				case results <- password:
					return
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (pc *PasswordCracker) testHTTP(password string) bool {
	url := fmt.Sprintf("%s://%s:%d", pc.config.Protocol, pc.config.Target, pc.config.Port)

	client := &http.Client{
		Timeout: pc.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.SetBasicAuth(pc.config.Username, password)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider any 2xx status as successful authentication
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// testHTTPLogin tests login endpoints using POST requests with form data or JSON
func (pc *PasswordCracker) testHTTPLogin(password string) bool {
	// Build the full URL
	endpoint := pc.config.Endpoint
	if endpoint == "" {
		endpoint = "/"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	baseURL := fmt.Sprintf("%s://%s:%d%s", pc.config.Protocol, pc.config.Target, pc.config.Port, endpoint)

	// Determine method (default to POST for login endpoints)
	method := pc.config.Method
	if method == "" {
		method = "POST"
	}

	var body io.Reader
	var contentType string

	// Prepare request body based on content type
	if pc.config.ContentType == "application/json" {
		// JSON payload
		payload := make(map[string]string)
		usernameField := pc.config.UsernameField
		if usernameField == "" {
			usernameField = "username"
		}
		passwordField := pc.config.PasswordField
		if passwordField == "" {
			passwordField = "password"
		}
		payload[usernameField] = pc.config.Username
		payload[passwordField] = password

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		body = bytes.NewBuffer(jsonData)
		contentType = "application/json"
	} else {
		// Form URL encoded (default)
		usernameField := pc.config.UsernameField
		if usernameField == "" {
			usernameField = "username"
		}
		passwordField := pc.config.PasswordField
		if passwordField == "" {
			passwordField = "password"
		}

		formData := url.Values{}
		formData.Set(usernameField, pc.config.Username)
		formData.Set(passwordField, password)
		body = strings.NewReader(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequest(method, baseURL, body)
	if err != nil {
		return false
	}

	// Set content type
	req.Header.Set("Content-Type", contentType)

	// Add custom headers
	if pc.config.CustomHeaders != nil {
		for key, value := range pc.config.CustomHeaders {
			req.Header.Set(key, value)
		}
	}

	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	// Configure HTTP client
	client := &http.Client{
		Timeout: pc.config.Timeout,
	}

	if !pc.config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Read response body for keyword analysis
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// If we can't read body, just check status code
		return pc.checkSuccessByStatusCode(resp.StatusCode)
	}
	bodyStr := string(bodyBytes)

	// Check success by status code
	if pc.checkSuccessByStatusCode(resp.StatusCode) {
		// If failure keywords are specified and found, it's not a success
		if len(pc.config.FailureKeywords) > 0 {
			for _, keyword := range pc.config.FailureKeywords {
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
					return false
				}
			}
		}
		return true
	}

	// Check success by keywords in response body
	if len(pc.config.SuccessKeywords) > 0 {
		for _, keyword := range pc.config.SuccessKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
				// Make sure failure keywords are not present
				if len(pc.config.FailureKeywords) > 0 {
					for _, failKeyword := range pc.config.FailureKeywords {
						if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(failKeyword)) {
							return false
						}
					}
				}
				return true
			}
		}
	}

	// Default: check for common success indicators
	// Redirects (3xx) often indicate successful login
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}

	// Check for common failure indicators
	failureIndicators := []string{"invalid", "incorrect", "wrong", "error", "failed", "denied", "unauthorized"}
	if len(pc.config.FailureKeywords) > 0 {
		failureIndicators = pc.config.FailureKeywords
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
			return false
		}
	}

	// If no specific indicators, consider 2xx as success
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// checkSuccessByStatusCode checks if the status code indicates success
func (pc *PasswordCracker) checkSuccessByStatusCode(statusCode int) bool {
	if len(pc.config.SuccessCodes) > 0 {
		for _, code := range pc.config.SuccessCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	}
	// Default: 2xx and 3xx are considered success
	return statusCode >= 200 && statusCode < 400
}

// testHTTPWithUser tests HTTP Basic Auth with specific username
func (pc *PasswordCracker) testHTTPWithUser(username, password string) bool {
	url := fmt.Sprintf("%s://%s:%d", pc.config.Protocol, pc.config.Target, pc.config.Port)

	client := &http.Client{
		Timeout: pc.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider any 2xx status as successful authentication
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// testHTTPLoginWithUser tests login endpoints using POST requests with form data or JSON for specific username
func (pc *PasswordCracker) testHTTPLoginWithUser(username, password string) bool {
	// Build the full URL
	endpoint := pc.config.Endpoint
	if endpoint == "" {
		endpoint = "/"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	baseURL := fmt.Sprintf("%s://%s:%d%s", pc.config.Protocol, pc.config.Target, pc.config.Port, endpoint)

	// Determine method (default to POST for login endpoints)
	method := pc.config.Method
	if method == "" {
		method = "POST"
	}

	var body io.Reader
	var contentType string

	// Prepare request body based on content type
	if pc.config.ContentType == "application/json" {
		// JSON payload
		payload := make(map[string]string)
		usernameField := pc.config.UsernameField
		if usernameField == "" {
			usernameField = "username"
		}
		passwordField := pc.config.PasswordField
		if passwordField == "" {
			passwordField = "password"
		}
		payload[usernameField] = username
		payload[passwordField] = password

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		body = bytes.NewBuffer(jsonData)
		contentType = "application/json"
	} else {
		// Form URL encoded (default)
		usernameField := pc.config.UsernameField
		if usernameField == "" {
			usernameField = "username"
		}
		passwordField := pc.config.PasswordField
		if passwordField == "" {
			passwordField = "password"
		}

		formData := url.Values{}
		formData.Set(usernameField, username)
		formData.Set(passwordField, password)
		body = strings.NewReader(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequest(method, baseURL, body)
	if err != nil {
		return false
	}

	// Set content type
	req.Header.Set("Content-Type", contentType)

	// Add custom headers
	if pc.config.CustomHeaders != nil {
		for key, value := range pc.config.CustomHeaders {
			req.Header.Set(key, value)
		}
	}

	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	// Configure HTTP client
	client := &http.Client{
		Timeout: pc.config.Timeout,
	}

	if !pc.config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Read response body for keyword analysis
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// If we can't read body, just check status code
		return pc.checkSuccessByStatusCode(resp.StatusCode)
	}
	bodyStr := string(bodyBytes)

	// Check success by status code
	if pc.checkSuccessByStatusCode(resp.StatusCode) {
		// If failure keywords are specified and found, it's not a success
		if len(pc.config.FailureKeywords) > 0 {
			for _, keyword := range pc.config.FailureKeywords {
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
					return false
				}
			}
		}
		return true
	}

	// Check success by keywords in response body
	if len(pc.config.SuccessKeywords) > 0 {
		for _, keyword := range pc.config.SuccessKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
				// Make sure failure keywords are not present
				if len(pc.config.FailureKeywords) > 0 {
					for _, failKeyword := range pc.config.FailureKeywords {
						if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(failKeyword)) {
							return false
						}
					}
				}
				return true
			}
		}
		return false
	}

	return false
}

// testSSHWithUser tests SSH authentication with specific username
func (pc *PasswordCracker) testSSHWithUser(username, password string) bool {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         pc.config.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", pc.config.Target, pc.config.Port), config)
	if err != nil {
		return false
	}

	if client != nil {
		client.Close()
	}
	return true
}

func (pc *PasswordCracker) testSSH(password string) bool {
	config := &ssh.ClientConfig{
		User: pc.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         pc.config.Timeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", pc.config.Target, pc.config.Port), config)
	if err != nil {
		return false
	}

	if client != nil {
		client.Close()
	}
	return true
}

func (pc *PasswordCracker) testHash(password, targetHash string) bool {
	// Check if it's a bcrypt hash first
	if strings.HasPrefix(targetHash, "$2a$") ||
		strings.HasPrefix(targetHash, "$2b$") ||
		strings.HasPrefix(targetHash, "$2y$") {
		err := bcrypt.CompareHashAndPassword([]byte(targetHash), []byte(password))
		return err == nil
	}

	// Try other hash algorithms
	hashTests := []struct {
		name string
		hash func() hash.Hash
	}{
		{"MD5", md5.New},
		{"SHA1", sha1.New},
		{"SHA256", sha256.New},
		{"SHA512", sha512.New},
	}

	for _, test := range hashTests {
		h := test.hash()
		h.Write([]byte(password))
		hashStr := hex.EncodeToString(h.Sum(nil))

		if hashStr == targetHash {
			return true
		}
	}

	return false
}

// Stop gracefully stops the password cracker
func (pc *PasswordCracker) Stop() {
	if pc.cancelFunc != nil {
		pc.cancelFunc()
	}
	pc.stats.EndTime = time.Now()
	pc.stats.Attempts = int(pc.attempts)
}

// GetStats returns current attack statistics
func (pc *PasswordCracker) GetStats() AttackStats {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	stats := pc.stats
	stats.Attempts = int(pc.attempts)

	if !stats.EndTime.IsZero() {
		stats.EndTime = time.Now()
	}

	return stats
}

// GetUserlist returns the loaded userlist
func (pc *PasswordCracker) GetUserlist() []string {
	return pc.userlist
}

// GetWordlist returns the loaded wordlist
func (pc *PasswordCracker) GetWordlist() []string {
	return pc.wordlist
}

// trackProgress displays real-time progress updates
func (pc *PasswordCracker) trackProgress(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentAttempts := atomic.LoadInt32(&pc.attempts)
			total := atomic.LoadInt32(&pc.total)
			
			if total == 0 {
				continue
			}

			percentage := float64(currentAttempts) / float64(total) * 100
			elapsed := time.Since(startTime)
			
			// Calculate attempts per second
			rate := float64(currentAttempts) / elapsed.Seconds()
			
			// Estimate time remaining
			var eta time.Duration
			if rate > 0 {
				remaining := total - currentAttempts
				eta = time.Duration(float64(remaining)/rate) * time.Second
			}

			// Only print if percentage changed by at least 1% or every 5 seconds
			currentProgress := int32(percentage)
			lastProgress := atomic.LoadInt32(&pc.lastProgress)
			
			if currentProgress > lastProgress || int(elapsed.Seconds())%5 == 0 {
				atomic.StoreInt32(&pc.lastProgress, currentProgress)
				
				// Format progress bar
				barWidth := 40
				filled := int(float64(barWidth) * percentage / 100)
				bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
				
				fmt.Printf("\r  Progress: [%s] %.1f%% | %d/%d | Rate: %.0f/s | ETA: %s     ",
					bar, percentage, currentAttempts, total, rate, formatDuration(eta))
			}
		}
	}
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "calculating..."
	}
	
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}
