# stalwart-users

Go API backend + SPA for managing accounts in Stalwart mail server's internal directory (accounts, email aliases, group memberships), deployed as a Kubernetes sidecar container.

## Overview

This project provides a management interface for Stalwart 1.0's internal directory. It manages user accounts, email aliases and group memberships through Stalwart's JMAP admin API; Stalwart stores the accounts and hashes the passwords. The app's own PostgreSQL database only holds the domain admin assignments. The application consists of a Go backend API and an SPA.

## Architecture

- **Backend**: Go service listening on port 3000.
- **Authentication**: Checks the login email and password against Stalwart's `/jmap/session` endpoint with HTTP Basic auth, then issues the app's own JWT session cookie. Accounts with two-factor auth can't sign in this way.
- **Account management**: Calls Stalwart's JMAP admin API (`x:Account`, `x:Domain`) with `STALWART_ADMIN_TOKEN`. New and changed passwords go to Stalwart as plaintext, so Stalwart's password policy applies and its rejections come back as 400. Stalwart 1.0 accounts can't be disabled, and groups are created in Stalwart's admin UI, not here.
- **Authorization**: Three roles.
  - **Full admins** (accounts with Stalwart's Admin role) can do everything.
  - **Domain admins** manage the accounts on the domains assigned to them in `directory.domain_admins` (created by the app on startup; full admins edit it via `/accounts/{name}/admin-domains`). They can create, edit, delete and reset passwords for those accounts, and manage their addresses and groups on those domains. They cannot set quotas, touch full admins, grant any admin rights, or act on a peer domain admin who manages a domain they don't.
  - **Everyone else** can view their own account, edit its full name and change their own password; their addresses are read-only.
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
| PUT | `/accounts/{name}/password` | Change a password (own password needs `current_password`) |
| GET | `/accounts/{name}/admin-domains` | List the domains an account administers (full admins only) |
| PUT | `/accounts/{name}/admin-domains` | Replace the domains an account administers (full admins only) |

## Environment variables

| Name | Description | Default | Required |
|---|---|---|---|
| `STALWART_URL` | Stalwart server URL, for login checks and the JMAP admin API | | Yes |
| `STALWART_ADMIN_TOKEN` | Bearer token for Stalwart's JMAP admin API | | Yes |
| `DATABASE_URL` | PostgreSQL connection string for the `directory.domain_admins` table only | | Yes |
| `JWT_SECRET` | Secret that signs session cookies | | Yes |
| `CORS_ORIGIN` | Allowed CORS origin | `*` | No |
| `PATH_PREFIX` | Path prefix for production routing (e.g., `/manage/api`) | | No |
| `PORT` | Port the server listens on | `3000` | No |

## Development

### Prerequisites

- Go 1.24+
- A Stalwart 1.0 server and an admin API token
- PostgreSQL database with a `directory` schema (the app creates `directory.domain_admins` on startup)

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
