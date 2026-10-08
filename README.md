[![codecov](https://codecov.io/gh/MountainGoatATU/GoatVaultServer/graph/badge.svg?token=B5HBATGFL2)](https://codecov.io/gh/MountainGoatATU/GoatVaultServer)
[![CodeScene Average Code Health](https://codescene.io/projects/76220/status-badges/average-code-health?component-name=Goatvaultserver)](https://codescene.io/projects/76220/architecture/biomarkers?component=Goatvaultserver)

# GoatVaultServer

API server for GoatVault, a zero-knowledge password manager. The server stores
users and their encrypted vaults and handles authentication, email verification,
optional TOTP-based MFA, and refresh-token rotation. It never sees a user's
master password or the decrypted vault.

## Requirements

- Python >=3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- A MongoDB database

## Installation

### Clone Repository

```bash
git clone https://github.com/MountainGoatATU/GoatVaultServer.git
cd GoatVaultServer
```

### Install dependencies

#### Using uv (recommended)

```bash
uv sync
```

#### Using pip

```bash
pip install -e .
```

## Configuration

Copy the example environment file and fill in the values:

cp .env.example .env

| Variable                                              | Description                                       |
| ----------------------------------------------------- | ------------------------------------------------- |
| `MONGODB_URL`                                         | MongoDB connection string                         |
| `DATABASE_NAME`                                       | Database name                                     |
| `JWT_SECRET` / `JWT_ALGORITHM`                        | Signing secret and algorithm (default `HS256`)    |
| `ISSUER`                                              | JWT issuer claim                                  |
| `ACCESS_TOKEN_EXP_MINUTES` / `REFRESH_TOKEN_EXP_DAYS` | Token lifetimes                                   |
| `MFA_SECRET_KEY`                                      | Key used to encrypt stored TOTP secrets           |
| `MAIL_*`                                              | SMTP credentials used for verification emails     |
| `SERVER_URL`                                          | Public base URL, used to build verification links |
| `ENVIRONMENT`                                         | `development` or `production`                     |

## Usage

### Production Server

```bash
uv run task server
```

### Development Server

```bash
uv run task dev
```

### Run tests with coverage

```bash
uv run task test
```

Visit http://localhost:8000/docs for the interactive API documentation.

## Authentication flow

1. `POST /v1/auth/init` with the user's email returns the `authSalt`, a
   single-use `nonce`, and MFA/Shamir status. Unknown emails
   receive a fake salt and nonce.
2. The client derives the `authVerifier` with Argon2 and computes
   `proof = HMAC-SHA256(authVerifier, nonce)`.
3. `POST /v1/auth/verify` with the user id and proof returns a JWT and a
   refresh token. An `mfaCode` is required when MFA is enabled.
4. `POST /v1/auth/refresh` rotates the refresh token and `POST /v1/auth/logout`
   revokes it.

Nonces expire after two minutes and are deleted after using. User routes require an access token in the header.

## API

| Method | Path                     | Description                                 |
| ------ | ------------------------ | ------------------------------------------- |
| GET    | `/`                      | Health check                                |
| POST   | `/v1/auth/register`      | Create a user and send a verification email |
| GET    | `/v1/auth/email/{token}` | Verify an email address                     |
| POST   | `/v1/auth/init`          | Start authentication                        |
| POST   | `/v1/auth/verify`        | Complete authentication and issue tokens    |
| POST   | `/v1/auth/refresh`       | Rotate a refresh token                      |
| POST   | `/v1/auth/logout`        | Revoke a refresh token                      |
| GET    | `/v1/users/{userId}`     | Get a user                                  |
| PATCH  | `/v1/users/{userId}`     | Update a user                               |
| DELETE | `/v1/users/{userId}`     | Delete a user                               |
