package curlparser

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/letgo/cracker"
	"github.com/letgo/ddos"
)

// CurlConfig represents parsed cURL command configuration
type CurlConfig struct {
	URL             string
	Method          string
	Headers         map[string]string
	Data            string
	ContentType     string
	FollowRedirects bool
	Timeout         time.Duration
}

// ParseCurlCommand parses a bash cURL command and extracts relevant information
func ParseCurlCommand(curlCmd string) (*CurlConfig, error) {
	config := &CurlConfig{
		Method:          "GET",
		Headers:         make(map[string]string),
		Timeout:         10 * time.Second,
		FollowRedirects: false,
	}

	// Remove line continuations and normalize whitespace
	curlCmd = strings.ReplaceAll(curlCmd, "\\\n", " ")
	curlCmd = strings.ReplaceAll(curlCmd, "\\", "")
	curlCmd = regexp.MustCompile(`\s+`).ReplaceAllString(curlCmd, " ")
	curlCmd = strings.TrimSpace(curlCmd)

	// Remove 'curl' command prefix if present
	curlCmd = regexp.MustCompile(`^curl\s+`).ReplaceAllString(curlCmd, "")

	// Split into tokens (preserving quoted strings)
	tokens := tokenizeCurl(curlCmd)

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]

		switch {
		case token == "-X" || token == "--request":
			if i+1 < len(tokens) {
				config.Method = strings.ToUpper(tokens[i+1])
				i++
			}
		case token == "-H" || token == "--header":
			if i+1 < len(tokens) {
				header := unquote(tokens[i+1])
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					config.Headers[key] = value

					// Track Content-Type
					if strings.ToLower(key) == "content-type" {
						config.ContentType = value
					}
				}
				i++
			}
		case token == "-d" || token == "--data" || token == "--data-raw" || token == "--data-binary":
			if i+1 < len(tokens) {
				config.Data = unquote(tokens[i+1])
				// If method not explicitly set, POST is implied with -d
				if config.Method == "GET" {
					config.Method = "POST"
				}
				i++
			}
		case token == "-L" || token == "--location":
			config.FollowRedirects = true
		case token == "--max-time" || token == "-m":
			if i+1 < len(tokens) {
				if timeout, err := strconv.Atoi(tokens[i+1]); err == nil {
					config.Timeout = time.Duration(timeout) * time.Second
				}
				i++
			}
		case !strings.HasPrefix(token, "-") && config.URL == "":
			// This is likely the URL
			config.URL = unquote(token)
		}
	}

	// Infer Content-Type from data if not set
	if config.Data != "" && config.ContentType == "" {
		if strings.HasPrefix(strings.TrimSpace(config.Data), "{") {
			config.ContentType = "application/json"
		} else {
			config.ContentType = "application/x-www-form-urlencoded"
		}
	}

	if config.URL == "" {
		return nil, fmt.Errorf("no URL found in cURL command")
	}

	return config, nil
}

// tokenizeCurl splits a cURL command into tokens, preserving quoted strings
func tokenizeCurl(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for i, ch := range cmd {
		switch {
		case (ch == '"' || ch == '\'') && (i == 0 || cmd[i-1] != '\\'):
			if !inQuote {
				inQuote = true
				quoteChar = ch
				current.WriteRune(ch)
			} else if ch == quoteChar {
				inQuote = false
				quoteChar = 0
				current.WriteRune(ch)
			} else {
				current.WriteRune(ch)
			}
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// unquote removes surrounding quotes from a string
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ExtractFieldsFromData attempts to extract username and password field names from POST data
func ExtractFieldsFromData(data string, contentType string) (usernameField, passwordField string, fields map[string]string) {
	fields = make(map[string]string)

	if strings.Contains(contentType, "json") {
		// Parse JSON data
		fields = parseJSONFields(data)
	} else {
		// Parse form-urlencoded data
		fields = parseFormFields(data)
	}

	// Try to identify username and password fields
	for key := range fields {
		keyLower := strings.ToLower(key)
		if usernameField == "" && (strings.Contains(keyLower, "user") || strings.Contains(keyLower, "email") || strings.Contains(keyLower, "login")) {
			usernameField = key
		}
		if passwordField == "" && (strings.Contains(keyLower, "pass") || strings.Contains(keyLower, "pwd")) {
			passwordField = key
		}
	}

	// Defaults
	if usernameField == "" {
		usernameField = "username"
	}
	if passwordField == "" {
		passwordField = "password"
	}

	return usernameField, passwordField, fields
}

// parseJSONFields extracts field names from JSON data
func parseJSONFields(data string) map[string]string {
	fields := make(map[string]string)

	// Simple JSON parsing - find "key": "value" patterns
	re := regexp.MustCompile(`"([^"]+)"\s*:\s*"[^"]*"`)
	matches := re.FindAllStringSubmatch(data, -1)

	for _, match := range matches {
		if len(match) > 1 {
			fields[match[1]] = ""
		}
	}

	return fields
}

// parseFormFields extracts field names from form-urlencoded data
func parseFormFields(data string) map[string]string {
	fields := make(map[string]string)

	pairs := strings.Split(data, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) >= 1 {
			key, _ := url.QueryUnescape(kv[0])
			fields[key] = ""
		}
	}

	return fields
}

// ToAttackConfig converts CurlConfig to cracker.AttackConfig
func (cc *CurlConfig) ToAttackConfig() (*cracker.AttackConfig, error) {
	// Parse URL
	parsedURL, err := url.Parse(cc.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	protocol := parsedURL.Scheme
	if protocol == "" {
		protocol = "https"
	}

	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in URL")
	}

	port := 80
	if parsedURL.Port() != "" {
		port, _ = strconv.Atoi(parsedURL.Port())
	} else if protocol == "https" {
		port = 443
	}

	endpoint := parsedURL.Path
	if endpoint == "" {
		endpoint = "/"
	}

	// Extract username and password fields from data
	usernameField, passwordField, _ := ExtractFieldsFromData(cc.Data, cc.ContentType)

	config := &cracker.AttackConfig{
		Target:          host,
		Protocol:        protocol,
		Port:            port,
		Endpoint:        endpoint,
		Method:          cc.Method,
		UsernameField:   usernameField,
		PasswordField:   passwordField,
		ContentType:     cc.ContentType,
		CustomHeaders:   cc.Headers,
		FollowRedirects: cc.FollowRedirects,
		Timeout:         cc.Timeout,
	}

	return config, nil
}

// LoadFromFile reads cURL commands from a file and returns parsed configurations
func LoadFromFile(filename string) ([]*CurlConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var configs []*CurlConfig
	var currentCurl strings.Builder
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if this is the start of a new curl command
		if strings.HasPrefix(line, "curl ") {
			// If we have a previous command, parse it
			if currentCurl.Len() > 0 {
				config, err := ParseCurlCommand(currentCurl.String())
				if err == nil {
					configs = append(configs, config)
				}
				currentCurl.Reset()
			}
			currentCurl.WriteString(line)
		} else if currentCurl.Len() > 0 {
			// Continue building current command
			currentCurl.WriteString(" ")
			currentCurl.WriteString(line)
		}
	}

	// Parse the last command
	if currentCurl.Len() > 0 {
		config, err := ParseCurlCommand(currentCurl.String())
		if err == nil {
			configs = append(configs, config)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no valid cURL commands found in file")
	}

	return configs, nil
}

// ToDDoSConfig converts CurlConfig to ddos.DDoSConfig
func (cc *CurlConfig) ToDDoSConfig() (*ddos.DDoSConfig, error) {
	if cc.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}

	config := &ddos.DDoSConfig{
		TargetURL:        cc.URL,
		Method:           cc.Method,
		Headers:          cc.Headers,
		Body:             cc.Data,
		ContentType:      cc.ContentType,
		FollowRedirects:  cc.FollowRedirects,
		Timeout:          cc.Timeout,
		MaxThreads:       100,              // Default threads
		Duration:         60 * time.Second, // Default duration
		AttackMode:       ddos.ModeFlood,   // Default mode
		ReuseConnections: true,             // Better performance
		SlowlorisDelay:   10 * time.Second, // Default slowloris delay
	}

	// Use shorter timeout for DDoS (faster failures)
	if config.Timeout > 5*time.Second {
		config.Timeout = 5 * time.Second
	}

	return config, nil
}

// LoadDDoSFromFile reads cURL commands from a file and returns DDoS configurations
func LoadDDoSFromFile(filename string) ([]*ddos.DDoSConfig, error) {
	curlConfigs, err := LoadFromFile(filename)
	if err != nil {
		return nil, err
	}

	var ddosConfigs []*ddos.DDoSConfig
	for _, curlConfig := range curlConfigs {
		ddosConfig, err := curlConfig.ToDDoSConfig()
		if err != nil {
			continue // Skip invalid configs
		}
		ddosConfigs = append(ddosConfigs, ddosConfig)
	}

	if len(ddosConfigs) == 0 {
		return nil, fmt.Errorf("no valid DDoS configurations found in file")
	}

	return ddosConfigs, nil
}
