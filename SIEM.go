package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	siemLogsMutex sync.RWMutex
	siemLogs      []SIEMlog
)

type Auth struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

type LogEntry struct {
	Email     string `json:"email"`
	Timestamp string `json:"timestamp"`
	Success   bool   `json:"success"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type Config struct {
	APIBaseURL      string
	PollingInterval time.Duration
	CredentialsFile string
}

type ServiceSIEM struct {
	config     Config
	httpClient *http.Client
	jwtToken   string
}

type SIEMlog struct {
	User      string `json:"user"`
	Timestamp string `json:"timestamp"`
	Status    bool   `json:"status"`
	Level     int    `json:"level"`
	Message   string `json:"message"`
}

func updateSIEMLogs(logs []SIEMlog) {
	siemLogsMutex.Lock()
	defer siemLogsMutex.Unlock()
	siemLogs = logs
	log.Printf("Updated SIEM logs. Current count: %d", len(siemLogs))
}

func validateAuth(auth Auth) bool {
	pattern := `^[A-Za-z0-9]+$`
	re := regexp.MustCompile(pattern)
	return re.MatchString(auth.Email) && re.MatchString(auth.Password)
}

func getSIEMLogs() []SIEMlog {
	siemLogsMutex.RLock()
	defer siemLogsMutex.RUnlock()
	result := make([]SIEMlog, len(siemLogs))
	copy(result, siemLogs)
	return result
}

func setupAPI() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
			return
		}
		http.FileServer(http.Dir(".")).ServeHTTP(w, r)
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var auth Auth
		if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if !validateAuth(auth) {
			http.Error(w, "May contains only A-Za-z and 0-9", http.StatusBadRequest)
			return
		}

		// --------------------------------------------

		client := &http.Client{Timeout: 5 * time.Second}
		jsonData, err := json.Marshal(auth)
		if err != nil {
			http.Error(w, "Failed to process authentication data", http.StatusInternalServerError)
			return
		}

		req, err := http.NewRequest("POST", "http://localhost:7777/api/login", bytes.NewBuffer(jsonData))
		if err != nil {
			http.Error(w, "Failed to create auth request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			var authResp AuthResponse
			if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
				return
			}
			json.NewEncoder(w).Encode(AuthResponse{Token: authResp.Token})
			return
		} else {
			http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		}
	})

	mux.HandleFunc("/api/protected/siem-logs", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		logs := getSIEMLogs()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})

	return mux
}

func NewServiceSIEM(config Config) *ServiceSIEM {
	return &ServiceSIEM{
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *ServiceSIEM) Login() error {
	authData := Auth{
		Email:    os.Getenv("EMAIL"),
		Password: os.Getenv("PASSWORD"),
	}

	jsonData, err := json.Marshal(authData)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %v", err)
	}

	url := fmt.Sprintf("%s/api/login", s.config.APIBaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %v", err)
	}

	s.jwtToken = authResp.Token
	log.Println("Login successful")
	return nil
}

func (s *ServiceSIEM) FetchLogs() ([]LogEntry, error) {
	if s.jwtToken == "" {
		return nil, fmt.Errorf("not authenticated")
	}

	url := fmt.Sprintf("%s/api/protected/logs", s.config.APIBaseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", s.jwtToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetching logs failed with status %d: %s", resp.StatusCode, string(body))
	}

	var logs []LogEntry
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return nil, fmt.Errorf("failed to decode logs response: %v", err)
	}

	log.Printf("Retrieved %d log entries", len(logs))
	return logs, nil
}

func (s *ServiceSIEM) StartPolling() {
	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	log.Println("Starting log polling with interval:", s.config.PollingInterval)

	for range ticker.C {
		logs, err := s.FetchLogs()
		if err != nil {
			log.Printf("Error fetching logs: %v", err)
			if err.Error() == "not authenticated" {
				if err := s.Login(); err != nil {
					log.Printf("Error re-authenticating: %v", err)
				}
			}
			continue
		}

		if len(logs) == 0 {
			log.Println("No logs found, skipping update")
			continue
		}

		sort.Slice(logs, func(i, j int) bool {
			return logs[i].Timestamp < logs[j].Timestamp
		})

		failedAttempts := make(map[string][]time.Time)

		var processedLogs []SIEMlog
		for _, logEntry := range logs {
			timestamp, err := time.Parse(time.RFC3339, logEntry.Timestamp)
			if err != nil {
				log.Printf("Error parsing timestamp %s: %v", logEntry.Timestamp, err)
				continue
			}

			level := 0
			message := "login attempt"

			if !logEntry.Success {
				failedAttempts[logEntry.Email] = append(failedAttempts[logEntry.Email], timestamp)

				// 3+ НЕУДАЧНЫЕ попытки за 1 минуту = брутфорс
				attempts := failedAttempts[logEntry.Email]
				if len(attempts) >= 3 {
					lastIdx := len(attempts) - 1
					timeDiff := attempts[lastIdx].Sub(attempts[lastIdx-2])

					if timeDiff <= 1*time.Minute {
						level = 1
						message = "brute force attack"
						log.Printf("Detected brute force attack from %s: %d failed attempts in %v",
							logEntry.Email, len(attempts), timeDiff)
					}
				}
			}

			siemLog := SIEMlog{
				User:      logEntry.Email,
				Timestamp: logEntry.Timestamp,
				Status:    logEntry.Success,
				Level:     level,
				Message:   message,
			}

			processedLogs = append(processedLogs, siemLog)
		}

		if len(processedLogs) > 0 {
			updateSIEMLogs(processedLogs)
		}
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	_, err := os.Stat("index.html")
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("index.html not found in working directory")
		}
		log.Fatalf("Error checking index.html: %v", err)
	}

	config := Config{
		APIBaseURL:      "http://localhost:7777", // Внешний API с логами
		PollingInterval: 5 * time.Second,
		CredentialsFile: "credentials.json",
	}

	siem := NewServiceSIEM(config)

	if err := siem.Login(); err != nil {
		log.Printf("Failed to login to external API: %v", err)
	}

	mux := setupAPI()

	webServerAddr := "localhost:8080"
	go func() {
		log.Printf("Starting web server at http://%s", webServerAddr)
		if err := http.ListenAndServe(webServerAddr, mux); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	siem.StartPolling()
}
