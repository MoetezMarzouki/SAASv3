// auth_functions.go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// Initialize DB function that should be called from main.go
func InitializeAuth(db *sql.DB) {
	DB = db
	createTables()
}

const Version = "1.0.0"

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Password is not exposed in JSON responses
	Email    string `json:"email"`
}

// Credentials represents login request
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Session represents a user session
type Session struct {
	Token      string
	UserID     int
	Expiration time.Time
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string // Optional: for client certificate verification
	ClientAuth tls.ClientAuthType
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// Sessions stores active sessions
var Sessions = make(map[string]Session)

// createTables creates required database tables
func createTables() {
	// Create users table
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL
		)
	`)
	if err != nil {
		panic(err)
	}

	// Create sessions table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token VARCHAR(255) PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id),
			expiration TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		panic(err)
	}
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	// Validate input
	if req.Username == "" || req.Password == "" || req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Username, password, and email are required")
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not hash password")
		return
	}

	// Create the user - using PostgreSQL parameter placeholders ($1, $2, $3)
	var id int
	err = DB.QueryRow(
		"INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id",
		req.Username, string(hashedPassword), req.Email,
	).Scan(&id)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			// Check PostgreSQL error codes
			if pqErr.Code == "23505" { // Unique violation
				respondWithError(w, http.StatusConflict, "Username or email already exists")
				return
			}
		}
		respondWithError(w, http.StatusInternalServerError, "Could not register user")
		return
	}

	// Create a session for the new user
	token, err := generateToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not generate session token")
		return
	}

	expiration := time.Now().Add(24 * time.Hour)
	_, err = DB.Exec(
		"INSERT INTO sessions (token, user_id, expiration) VALUES ($1, $2, $3)",
		token, id, expiration,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create session")
		return
	}

	// Store session in memory too for faster lookups
	Sessions[token] = Session{
		Token:      token,
		UserID:     id,
		Expiration: expiration,
	}

	// Return user information and token
	user := User{
		ID:       id,
		Username: req.Username,
		Email:    req.Email,
	}

	respondWithJSON(w, http.StatusCreated, AuthResponse{
		Token: token,
		User:  user,
	})
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	// Fetch the user from database
	var user User
	var hashedPassword string
	err := DB.QueryRow(
		"SELECT id, username, password, email FROM users WHERE username = $1",
		creds.Username,
	).Scan(&user.ID, &user.Username, &hashedPassword, &user.Email)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password)); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Create a session token
	token, err := generateToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not generate session token")
		return
	}

	// Store the session
	expiration := time.Now().Add(24 * time.Hour)
	_, err = DB.Exec(
		"INSERT INTO sessions (token, user_id, expiration) VALUES ($1, $2, $3)",
		token, user.ID, expiration,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create session")
		return
	}

	// Store session in memory too for faster lookups
	Sessions[token] = Session{
		Token:      token,
		UserID:     user.ID,
		Expiration: expiration,
	}

	// Return user information and token
	respondWithJSON(w, http.StatusOK, AuthResponse{
		Token: token,
		User:  user,
	})
}

// AuthMiddleware verifies authentication tokens
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		// Check if the header format is correct
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondWithError(w, http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
			return
		}

		token := parts[1]

		// Check if session exists in memory
		session, exists := Sessions[token]
		if !exists {
			// Try to fetch from database
			var userID int
			var expiration time.Time
			err := DB.QueryRow(
				"SELECT user_id, expiration FROM sessions WHERE token = $1",
				token,
			).Scan(&userID, &expiration)

			if err != nil {
				respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}

			// Check if session has expired
			if expiration.Before(time.Now()) {
				// Delete expired session
				DB.Exec("DELETE FROM sessions WHERE token = $1", token)
				respondWithError(w, http.StatusUnauthorized, "Token has expired")
				return
			}

			// Store in memory for next time
			session = Session{
				Token:      token,
				UserID:     userID,
				Expiration: expiration,
			}
			Sessions[token] = session
		} else if session.Expiration.Before(time.Now()) {
			// Session has expired
			delete(Sessions, token)
			DB.Exec("DELETE FROM sessions WHERE token = $1", token)
			respondWithError(w, http.StatusUnauthorized, "Token has expired")
			return
		}

		// Add user ID to request context
		ctx := r.Context()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	// Check if the header format is correct
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondWithError(w, http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
		return
	}

	token := parts[1]

	// Delete session
	delete(Sessions, token)
	DB.Exec("DELETE FROM sessions WHERE token = $1", token)

	w.WriteHeader(http.StatusNoContent)
}

// GetCurrentUser returns the current user based on the token
func GetCurrentUser(token string) (User, error) {
	var user User

	// Check if session exists
	session, exists := Sessions[token]
	if !exists {
		// Try to fetch from database
		var userID int
		var expiration time.Time
		err := DB.QueryRow(
			"SELECT user_id, expiration FROM sessions WHERE token = $1",
			token,
		).Scan(&userID, &expiration)

		if err != nil {
			return user, errors.New("invalid or expired token")
		}

		// Check if session has expired
		if expiration.Before(time.Now()) {
			// Delete expired session
			DB.Exec("DELETE FROM sessions WHERE token = $1", token)
			return user, errors.New("token has expired")
		}

		session = Session{
			Token:      token,
			UserID:     userID,
			Expiration: expiration,
		}
		Sessions[token] = session
	} else if session.Expiration.Before(time.Now()) {
		// Session has expired
		delete(Sessions, token)
		DB.Exec("DELETE FROM sessions WHERE token = $1", token)
		return user, errors.New("token has expired")
	}

	// Fetch user from database
	err := DB.QueryRow(
		"SELECT id, username, email FROM users WHERE id = $1",
		session.UserID,
	).Scan(&user.ID, &user.Username, &user.Email)

	if err != nil {
		return user, errors.New("user not found")
	}

	return user, nil
}

// ConfigureTLS sets up TLS for the server
func ConfigureTLS(config TLSConfig) *tls.Config {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// If CA file is provided, set up client certificate verification
	if config.CAFile != "" {
		caCert, err := ioutil.ReadFile(config.CAFile)
		if err != nil {
			log.Fatalf("Failed to read CA certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatalf("Failed to append CA certificate to pool")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = config.ClientAuth
	}

	return tlsConfig
}

// StartTLSServer starts the HTTPS server
func StartTLSServer(addr string, handler http.Handler, tlsConfig *tls.Config) {
	server := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS server on %s", addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

// HealthHandler handles health check requests
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
		Version:   Version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// generateToken generates a random token
func generateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(b)
	return base64.URLEncoding.EncodeToString(hash[:]), nil
}

// respondWithError returns an error response
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, ErrorResponse{Error: message})
}

// respondWithJSON returns a JSON response
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// GenerateClientCert generates a command to create a client certificate for testing
func GenerateClientCert() string {
	// This is just a helper function to provide commands for generating certificates
	return `
# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyAuth CA"

# Generate server key and certificate signing request (CSR)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=auth-service.default.svc.cluster.local"

# Add Subject Alternative Names for additional DNS names (important for Kubernetes)
cat > server-ext.cnf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = auth-service
DNS.2 = auth-service.default
DNS.3 = auth-service.default.svc
DNS.4 = auth-service.default.svc.cluster.local
EOF

# Sign the server CSR with the CA key (including SANs)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server-ext.cnf

# Generate client key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client"

# Sign the client CSR with the CA key
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
`
}
