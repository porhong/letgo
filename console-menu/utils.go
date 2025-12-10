package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/letgo/proxy"
	"github.com/letgo/scanner"
	"github.com/letgo/secretscanner"
)

// writeResult writes successful credentials to results.txt file (thread-safe)
func (m *Menu) writeResult(urlStr, username, password string) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	file, err := os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open results.txt: %w", err)
	}
	defer file.Close()

	resultLine := fmt.Sprintf("%s|%s|%s\n", urlStr, username, password)
	if _, err := file.WriteString(resultLine); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	return nil
}

// writeSecretResultsToFile writes secret scan results to a file
func (m *Menu) writeSecretResultsToFile(results []secretscanner.ScanResult) error {
	file, err := os.Create("secrets-found.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := fmt.Sprintf("%s\n%s\n%s\n\n",
		strings.Repeat("=", 70),
		"SECRET SCAN RESULTS",
		strings.Repeat("=", 70))
	if _, err := writer.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Group by severity
	resultsBySeverity := make(map[string][]secretscanner.ScanResult)
	for _, result := range results {
		resultsBySeverity[result.Severity] = append(resultsBySeverity[result.Severity], result)
	}

	// Write results grouped by severity
	for _, severity := range []string{"high", "medium", "low"} {
		if severityResults := resultsBySeverity[severity]; len(severityResults) > 0 {
			severityHeader := fmt.Sprintf("\n[%s] SEVERITY FINDINGS (%d):\n%s\n",
				strings.ToUpper(severity), len(severityResults), strings.Repeat("-", 70))
			if _, err := writer.WriteString(severityHeader); err != nil {
				return fmt.Errorf("failed to write severity header: %w", err)
			}

			for i, result := range severityResults {
				resultLine := fmt.Sprintf("\n[%d] %s\n", i+1, result.URL)
				resultLine += fmt.Sprintf("    Type: %s | Severity: %s\n", strings.ToUpper(result.Type), strings.ToUpper(result.Severity))
				resultLine += fmt.Sprintf("    Location: %s\n", result.Location)
				if result.FilePath != "" {
					resultLine += fmt.Sprintf("    File: %s\n", result.FilePath)
				}
				resultLine += fmt.Sprintf("    Pattern: %s\n", result.Pattern)
				if result.Value != "" {
					resultLine += fmt.Sprintf("    Value: %s\n", result.Value)
				}
				resultLine += fmt.Sprintf("    Description: %s\n", result.Description)
				resultLine += "\n"

				if _, err := writer.WriteString(resultLine); err != nil {
					return fmt.Errorf("failed to write result: %w", err)
				}
			}
		}
	}

	return nil
}

// writeValidEndpointsToFile writes valid endpoints to valid-url.txt
func (m *Menu) writeValidEndpointsToFile(results []scanner.EndpointResult) error {
	file, err := os.Create("valid-url.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write each valid endpoint URL to the file
	for _, result := range results {
		if _, err := writer.WriteString(result.URL + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

// getTechnologyRecommendations returns attack strategy recommendations based on detected technology
func getTechnologyRecommendations(tech string) string {
	recommendations := map[string]string{
		"php":     "Common endpoints: /login.php, /admin.php | Default form fields: username, password",
		"java":    "Common endpoints: /j_security_check, /login.do | Watch for session tokens",
		"python":  "Django/Flask detected | Look for csrfmiddlewaretoken in forms",
		"dotnet":  "ASP.NET detected | Common endpoints: /Account/Login.aspx | Check for ViewState",
		"nextjs":  "Next.js (SSR) detected | API routes at /api/auth/* | May use JSON authentication",
		"nuxtjs":  "Nuxt.js (SSR) detected | API routes at /api/* | May use JSON authentication",
		"angular": "Angular (SPA) detected | Likely uses REST API | Check /api/login endpoints",
		"react":   "React (SPA) detected | Likely uses REST API | Check /api/auth endpoints",
		"vue":     "Vue.js detected | Likely uses REST API | Check /api/login endpoints",
		"node":    "Node.js/Express detected | Check for express session cookies",
		"ruby":    "Ruby on Rails detected | CSRF token required | Check /users/sign_in",
	}

	if rec, ok := recommendations[strings.ToLower(tech)]; ok {
		return rec
	}
	return "No specific recommendations available"
}

// writeProxiesToFile writes proxies to a file (thread-safe)
func (m *Menu) writeProxiesToFile(proxies []proxy.ProxyResult, filename string) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := fmt.Sprintf("# Proxy List - Total: %d\n", len(proxies))
	header += "# Format: protocol://host:port\n"
	header += fmt.Sprintf("# Generated: %s\n\n", strings.TrimSpace(strings.Split(fmt.Sprintf("%v", os.Stdout), " ")[0]))
	if _, err := writer.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write each proxy
	for _, proxy := range proxies {
		proxyLine := proxy.FormatProxy() + "\n"
		if _, err := writer.WriteString(proxyLine); err != nil {
			return fmt.Errorf("failed to write proxy: %w", err)
		}
	}

	return nil
}
