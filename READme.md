# SAASv3 - Secure Authentication Service

## Overview
SAASv3 is a robust authentication service built with Go and React, featuring TLS-secured registration and login functionality. The project provides a secure foundation for user authentication in web applications with both REST API and gRPC support.

## Features
- **Secure User Registration**: Create new user accounts with encrypted passwords
- **Authentication**: Secure login with token-based session management
- **Session Management**: Persistent sessions with automatic expiration
- **TLS Security**: End-to-end encryption with certificate-based authentication
- **Health Monitoring**: Built-in health check endpoint
- **Dual Protocol Support**: 
  - REST API for web clients
  - gRPC for high-performance service-to-service communication

## Technical Stack
- **Backend**: Go (Golang)
- **Frontend**: React
- **Database**: PostgreSQL
- **Authentication**: JWT/Session tokens with bcrypt password hashing
- **Security**: TLS 1.2+ with optional client certificate verification

## API Endpoints

### REST Endpoints
- `POST /register` - Create a new user account
- `POST /login` - Authenticate and receive a session token
- `POST /logout` - End the current session
- `GET /health` - Check service health status

### Authentication Flow
1. Register a new user with username, password, and email
2. Login to receive a session token
3. Include the token in the Authorization header for protected requests:
   ```
   Authorization: Bearer {token}
   ```

## Setup Instructions

### Prerequisites
- Go 1.16+
- PostgreSQL
- Node.js and npm (for React frontend)
- OpenSSL (for certificate generation)

### Database Setup
The service automatically creates the required tables:
- `users` - Stores user information
- `sessions` - Manages active sessions

### Configuration
To generate certificates for TLS:
```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyAuth CA"

# Generate server key and certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=auth-service.default.svc.cluster.local"

# Add Subject Alternative Names
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

# Sign the server CSR with the CA key
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server-ext.cnf
```

### Running the Service
```bash
# Start the service
go run main.go

# Default ports:
# - HTTP: 8080
# - gRPC: 50051 (if configured)
```


## Development Notes
- The project uses both HTTP and gRPC, which can be configured to run on separate ports or on the same port with middleware routing
- The health endpoint (`/health`) returns service status and version information
- Password security uses bcrypt with appropriate cost factors

## License
[Specify your license here]

## Contributors
- [MoetezMarzouki](https://github.com/MoetezMarzouki)
- [Add other contributors]