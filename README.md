# stalwart-users

Go API backend + vanilla SPA for managing Stalwart mail server's SQL directory (accounts, email aliases, group memberships), deployed as a Kubernetes sidecar container.

## Overview

This project provides a management interface for Stalwart mail server's SQL directory. It allows administrators to manage user accounts, email aliases, and group memberships directly in the underlying PostgreSQL database. The application consists of a Go backend API and a vanilla JavaScript SPA.

## Architecture

- **Backend**: Go service listening on port 3000.
- **Authentication**: Validates JMAP sessions against the Stalwart server's `/jmap/session` endpoint.
- **Authorization**: Access is restricted to users listed in the `ADMIN_USERS` environment variable.
- **Frontend**: Vanilla HTML/JS/CSS SPA. In production, it is served by Stalwart's Applications feature.
- **Ingress**: API requests are typically proxied via a Gateway API HTTPRoute.

## API endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Health check endpoint |
| GET | `/accounts` | List all user accounts |
| GET | `/accounts/{name}` | Get details for a specific account |
| GET | `/accounts/{name}/emails` | List email aliases for an account |
| GET | `/accounts/{name}/groups` | List group memberships for an account |
| POST | `/accounts` | Create a new user account |
| POST | `/accounts/{name}/emails` | Add an email alias to an account |
| POST | `/accounts/{name}/groups` | Add an account to a group |
| PATCH | `/accounts/{name}` | Update account details (e.g., password) |
| DELETE | `/accounts/{name}` | Delete an account (cascades to aliases and groups) |
| DELETE | `/accounts/{name}/emails/{address}` | Remove an email alias |
| DELETE | `/accounts/{name}/groups/{group}` | Remove an account from a group |

## Environment variables

| Name | Description | Default | Required |
|---|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | | Yes |
| `STALWART_URL` | Stalwart server URL for JMAP session validation | `http://localhost:8080` | No |
| `ADMIN_USERS` | Comma-separated list of admin usernames | | No |
| `PATH_PREFIX` | Path prefix for production routing (e.g., `/manage/api`) | | No |
| `PORT` | Port the server listens on | `3000` | No |
| `SERVE_UI` | Local path to UI files to serve (development only) | | No |
| `AUTH_BYPASS` | Set to `true` to bypass authentication (development only) | `false` | No |

## Development

### Prerequisites

- Go 1.24+
- PostgreSQL database with the Stalwart `directory` schema

### Build

```bash
make build
```

### Run locally

```bash
make run
```

### Run tests

```bash
make test
```

## Deployment

- **Container Image**: `harbor.vaderrp.com/operinko-labs/stalwart-users`
- **CI/CD**: GitHub Actions builds the image on pushes to `main` and tags. Releases are triggered by tags.
- **SPA Deployment**: The SPA is packaged as a zip file in GitHub releases and should be registered in Stalwart. See [Stalwart app registration](docs/stalwart-app-registration.md) for details.

## License

Unlicensed
