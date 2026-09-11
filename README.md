# Containerized CLI Login System with 2FA (TOTP)

A secure, enterprise-grade command-line authentication system built in **Go** using **Gin** and **GORM**, containerized with **Docker** and backed by **PostgreSQL** with persistent volume storage.

---

## 🌟 Architectural Overview

The system follows a clean client-server architecture:
- **API Server (`cmd/server`)**: High-performance REST service built using **Gin** and **GORM**. It manages cryptographic password hashing (bcrypt), TOTP 2FA generation and validation (RFC 6238), account lockout enforcement, and database-backed session token lifecycles.
- **Interactive CLI (`cmd/cli`)**: Terminal REPL with dynamic prompt states, command history, tab-completion, and secure non-echoing password input.
- **Database (`postgres:16-alpine`)**: Containerized PostgreSQL instance with persistent Docker volume storage and explicit SQL migrations.

```
                      +-----------------------------+
                      |       Interactive CLI       |
                      |  (Prompt, History, Tab-Comp)|
                      +--------------+--------------+
                                     | HTTP REST
                                     v
                      +-----------------------------+
                      |      Gin REST API Server    |
                      |   (Auth, MFA, Middleware)   |
                      +--------------+--------------+
                                     | GORM ORM
                                     v
                      +-----------------------------+
                      |    PostgreSQL (Container)   |
                      |   (Volume-backed Storage)   |
                      +-----------------------------+
```

---

## 🚀 Key Features

1. **Authentication & Password Security**:
   - Registration with input validation (username regex and minimum 8-character password).
   - Passwords hashed using `golang.org/x/crypto/bcrypt` with default cryptographic cost.
   - Non-echoing masked password input in CLI using terminal raw mode (`golang.org/x/term`).

2. **RFC 6238 TOTP Two-Factor Authentication**:
   - 100% compatible with **Google Authenticator**, **Authy**, and standard TOTP apps.
   - 160-bit cryptographically secure Base32 secret generation.
   - Standard `otpauth://totp/...` URI generation and secret display.
   - Constant-time HMAC-SHA1 verification with time-drift window tolerance ($\pm 1$ step / 30s).
   - Can be enabled (`enable-2fa`) and disabled (`disable-2fa`) securely after authentication.

3. **Account Lockout Policy**:
   - Tracks consecutive failed login attempts per account.
   - Automatically locks account after 5 consecutive failures for 15 minutes (configurable).
   - Informs the user of remaining attempts before lockout and remaining lockout duration.
   - Successful authentication resets the failure counter.

4. **Session Management**:
   - Cryptographically random 256-bit hexadecimal session tokens (`crypto/rand`).
   - Database-backed session persistence with creation time, expiration timestamp, and revocation tracking.
   - Configurable session timeout (default 30 minutes).
   - Explicit `logout` command revokes the active session token immediately.

5. **Interactive CLI Usability**:
   - Dynamic prompt based on authentication state:
     - Logged out: `auth-cli> `
     - Logged in: `auth-cli (username)> `
   - Context-aware **Tab-completion** for available commands.
   - Persistent command history (stored at `/tmp/.auth_cli_history`).
   - Automatic user profile display immediately upon successful login.

6. **Database Persistence**:
   - Runs in PostgreSQL container with named Docker volume (`postgres_data`).
   - Data survives container restarts and crashes.
   - Schema defined in both explicit SQL migrations (`migrations/000001_init_schema.up.sql`) and GORM AutoMigrate.

---

## 📁 Repository Structure

```
auth-cli-system/
├── cmd/
│   ├── cli/
│   │   └── main.go                  # CLI application entrypoint
│   └── server/
│       └── main.go                  # Gin API server entrypoint & graceful shutdown
├── internal/
│   ├── api/
│   │   ├── handlers/
│   │   │   ├── auth_handler.go      # Register, Login, Logout HTTP handlers
│   │   │   ├── auth_handler_test.go # End-to-end API HTTP integration tests
│   │   │   ├── mfa_handler.go       # 2FA generate, enable, disable handlers
│   │   │   └── user_handler.go      # WhoAmI profile handler
│   │   ├── middleware/
│   │   │   └── auth_middleware.go   # Bearer token session authentication middleware
│   │   └── router.go                # Gin route registration & middleware pipeline
│   ├── cli/
│   │   ├── client.go                # HTTP client wrapper for API endpoints
│   │   ├── commands.go              # CLI command implementations & dispatch logic
│   │   ├── repl.go                  # Interactive Readline REPL with tab-completion & history
│   │   └── terminal.go              # Formatted profile tables, ANSI styling & masked input
│   ├── config/
│   │   └── config.go                # Centralized environment configuration
│   ├── database/
│   │   └── database.go              # PostgreSQL / SQLite GORM connection & migration runner
│   ├── models/
│   │   ├── session.go               # GORM Session entity
│   │   └── user.go                  # GORM User entity with lockout helpers
│   └── services/
│       ├── auth_service.go          # Core auth business logic (lockout, bcrypt, verification)
│       ├── auth_service_test.go     # Unit tests for registration, lockout, 2FA workflows
│       ├── session_service.go       # Session token generation, lookup, and revocation
│       ├── session_service_test.go  # Unit tests for session lifecycle
│       ├── test_helper_test.go      # Test setup helper with in-memory SQLite DB
│       ├── totp_service.go          # RFC 6238 TOTP implementation
│       └── totp_service_test.go     # Unit tests with RFC 6238 test vectors
├── migrations/
│   ├── 000001_init_schema.down.sql  # SQL schema rollback
│   └── 000001_init_schema.up.sql    # Explicit SQL schema definition
├── docker-compose.yml               # Container orchestration (PostgreSQL, Server, CLI)
├── Dockerfile                       # Multi-stage build for Server and CLI
├── Makefile                         # Build and test shortcuts
├── go.mod                           # Go module definition
└── README.md                        # Documentation and user guide
```

---

## 🛠️ Quickstart with Docker Compose

Ensure Docker and Docker Compose are installed.

### 1. Start the Database and Server
```bash
docker compose up -d postgres server
```
This will:
- Spin up PostgreSQL and create the persistent volume `postgres_data`.
- Execute database migrations.
- Start the Gin API server on `http://localhost:8080`.

### 2. Launch the Interactive CLI
```bash
docker compose run --rm cli
```
This attaches your terminal directly to the interactive containerized CLI!

### 3. Stop Containers
```bash
docker compose down
```
*(Note: Database data remains safe in the `postgres_data` volume).*

---

## 💻 Running Locally / in GitHub Codespaces

### 1. Start PostgreSQL (or use Docker for DB only)
```bash
docker compose up -d postgres
```
*(Alternatively, you can set `DB_DRIVER=sqlite` in environment variables for zero-dependency local testing).*

### 2. Build Binaries
```bash
make build
# Or manually:
go build -o bin/server ./cmd/server
go build -o bin/cli ./cmd/cli
```

### 3. Run the Server
```bash
./bin/server
# Or:
make run-server
```

### 4. Run the CLI in Another Terminal
```bash
./bin/cli
# Or:
make run-cli
```

---

## 📖 CLI Commands Reference

### Commands Before Login
| Command | Description |
| :--- | :--- |
| `register` | Prompts for username and password (with confirmation and masked input) to create an account. |
| `login` | Prompts for username and password. If 2FA is enabled, automatically prompts for the 6-digit TOTP code. Displays user profile upon success. |
| `help` | Lists available commands for the unauthenticated state. |
| `exit` | Quits the CLI application. |

### Commands After Login
| Command | Description |
| :--- | :--- |
| `whoami` | Displays current user profile (Username, Registration Date, MFA Status, Session Expiration, Last Login). |
| `enable-2fa` | Generates a 160-bit TOTP secret, displays secret key and `otpauth://` URI for Google Authenticator, and prompts for confirmation code. |
| `disable-2fa` | Prompts for confirmation and disables 2FA for the account. |
| `logout` | Revokes the active session token in the database and returns prompt to unauthenticated state. |
| `help` | Lists available commands for the authenticated state. |
| `exit` | Informs user and quits the CLI application. |

---

## 📊 Auto-Displayed User Profile Banner

Upon successful login or when running `whoami`, the system prints:

```
┌────────────────────────────────────────────────────────────┐
│                    CURRENT USER PROFILE                    │
├────────────────────────────────────────────────────────────┤
│ Username:          alice                                   │
│ Registration Date: 2026-09-11 02:45:10 UTC                 │
│ MFA Status:        ENABLED                                 │
│ Session Expiry:    Fri, 11 Sep 2026 03:15:10 UTC (in ~30m) │
│ Last Login:        Fri, 11 Sep 2026 02:40:02 UTC           │
└────────────────────────────────────────────────────────────┘
```

---

## 🧪 Running Unit & Integration Tests

The test suite covers:
- **TOTP Service**: RFC 6238 compliance, official known test vectors, drift window tolerance, and secret generation.
- **Auth Service**: Password hashing, input validation, duplicate usernames, lockout policy triggering after 5 failed attempts, lockout duration enforcement, and 2FA enrollment/verification.
- **Session Service**: 256-bit token generation, database storage, expiration enforcement, and revocation.
- **API Handlers**: End-to-end HTTP tests with `httptest.ResponseRecorder` across all endpoints and auth middleware.

Execute all tests with:
```bash
go test -v -race ./...
```

---

## 🔒 Security Specifications

- **Cryptographic Hashing**: `bcrypt` is intentionally slow and memory-hard to prevent offline brute-force attacks.
- **Timing Attack Mitigation**: All OTP code comparisons utilize `crypto/subtle.ConstantTimeCompare`.
- **Session Protection**: Session tokens are generated via `crypto/rand` (256-bit entropy) and strictly verified against database expiration timestamps and revocation lists.
- **Account Lockout**: Defends against credential stuffing and brute-force dictionary attacks.
- **Terminal Hygiene**: Terminal raw mode suppresses echo during password entry to prevent shoulder-surfing.
