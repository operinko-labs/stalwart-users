# stalwart-users

Go API backend + SPA for managing accounts in Stalwart mail server's internal directory (accounts, email aliases, group memberships), deployed as a Kubernetes sidecar container.

## Overview

This project provides a management interface for Stalwart 1.0's internal directory. It manages user accounts, email aliases and group memberships through Stalwart's JMAP admin API; Stalwart stores the accounts and hashes the passwords. The app's own PostgreSQL database only holds the domain admin assignments. The application consists of a Go backend API and an SPA.

## Architecture

- **Backend**: Go service listening on port 3000.
- **Authentication**: Users sign in through Stalwart's OIDC login (authorization code flow with PKCE, scope `openid offline_access`), so Stalwart's own login page handles passwords and two-factor auth. The app is a first-party OAuth client of Stalwart and registers itself at startup: a background task uses `STALWART_ADMIN_TOKEN` to create the `x:OAuthClient` (or update its secret, redirect URI and grant types), retrying every 5 to 60 seconds until Stalwart answers, without delaying the server. The client secret is derived from `JWT_SECRET` (`OIDC_CLIENT_SECRET` overrides it), so nothing is stored anywhere. Rotating `JWT_SECRET` rotates the client secret on the next start and signs everyone out. Sign-ins attempted before registration succeeds fail, either on Stalwart's own login page (unknown client or redirect URI, on a first start or after `OIDC_REDIRECT_URL` changes) or at the token exchange (`/login?error=signin`). `GET /auth/login` redirects the browser to Stalwart, `GET /auth/callback` exchanges the code, takes the userinfo `email` and requires it to match the primary address of a Stalwart User, then issues the app's own JWT session cookie and redirects to `/`. A failed sign-in lands on `/login?error=<denied|state|signin|no_mailbox|reauth>`. The user's OAuth tokens are kept in memory only (never in a cookie), so after a backend restart a session still works except for changing your own password, which asks the user to sign in again. The same happens whenever the stored tokens can't be refreshed or were revoked (for example after a password change). Signing out ends the app's session only, not the Stalwart login.
- **Account management**: Calls Stalwart's JMAP admin API (`x:Account`, `x:Domain`) with `STALWART_ADMIN_TOKEN`. New and changed passwords go to Stalwart as plaintext, so Stalwart's password policy applies and its rejections come back as 400. Non-admins and domain admins changing their own password go through Stalwart's `x:AccountPassword` as themselves, using their own access token, so Stalwart checks the current password and the two-factor code (answered as 400 `otp_required`; 401 `reauth_required` when the stored tokens are gone or can't be refreshed, e.g. after a restart or once they are revoked). Full admins changing their own password use the admin API without a current password. Stalwart 1.0 accounts can't be disabled, and groups are created in Stalwart's admin UI, not here.
- **Authorization**: Three roles.
  - **Full admins** (accounts with Stalwart's Admin role) can do everything.
  - **Domain admins** manage the accounts on the domains assigned to them in `directory.domain_admins` (created by the app on startup; full admins edit it via `/accounts/{name}/admin-domains`). They can create, edit, delete and reset passwords for those accounts, and manage their addresses and groups on those domains. They cannot set quotas, touch full admins, grant any admin rights, or act on a peer domain admin who manages a domain they don't.
  - **Everyone else** can view their own account, edit its full name and change their own password; their addresses are read-only.
- **Frontend**: React SPA. In production, it is served by Stalwart's Applications feature.
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
| GET | `/auth/login` | Start sign-in: redirects to Stalwart's login page |
| GET | `/auth/callback` | OIDC callback: sets the session cookie, redirects to `/` |
| GET | `/auth/me` | The signed-in user |
| POST | `/auth/logout` | End the app's session |
| PUT | `/accounts/{name}/password` | Change a password (own password needs `current_password`, plus `otp_code` when 2FA is on) |
| GET | `/accounts/{name}/admin-domains` | List the domains an account administers (full admins only) |
| PUT | `/accounts/{name}/admin-domains` | Replace the domains an account administers (full admins only) |

## Environment variables

| Name | Description | Default | Required |
|---|---|---|---|
| `STALWART_URL` | Stalwart server URL, for the JMAP admin API and `x:AccountPassword` | | Yes |
| `OIDC_ISSUER` | Stalwart's OIDC issuer URL (discovery at `<issuer>/.well-known/openid-configuration`), e.g. `https://mail.erinko.fi` | | Yes |
| `OIDC_CLIENT_ID` | Client ID of this app's OAuth client in Stalwart; the app registers it itself at startup. Must be unique per deployment that shares one Stalwart, because every start overwrites that client's secret and replaces its redirect URIs with exactly the configured one | | Yes |
| `OIDC_CLIENT_SECRET` | Optional override of the client secret (used with `client_secret_basic`). By default it is derived from `JWT_SECRET`. If set, it should be alphanumeric | derived | No |
| `OIDC_REDIRECT_URL` | Callback URL registered on that client: `https://<host>/api/auth/callback` | | Yes |
| `STALWART_ADMIN_TOKEN` | Bearer token for Stalwart's JMAP admin API. It must be allowed to manage OAuth clients (Stalwart's `sysOAuthClient*` permissions, which a full admin key has) | | Yes |
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

## Migrating from the SQL directory

The image also ships `/migrate-directory`, a one-shot tool that copies the old SQL directory (`directory.accounts`, `directory.emails`) into Stalwart's internal accounts. The accounts must already exist in Stalwart, one per active SQL account. It needs `DATABASE_URL` (the database with the old `directory` schema), `STALWART_URL` and `STALWART_ADMIN_TOKEN`.

```bash
/migrate-directory                          # dry run: prints what would change
/migrate-directory --apply                  # writes
/migrate-directory --apply --only a@x.com   # limit to these accounts (repeatable)
```

- Run a full dry run (no `--only`) first. `--only` doesn't check duplicates against the accounts it excludes.
- Password hashes are copied byte for byte. A secret that isn't a valid `{SSHA512}` hash stops the run before anything is written, naming the account.
- The tool only adds. It sets the description when SQL has one, grants the Admin role when SQL says admin, sets the disk quota when SQL has one, and adds aliases Stalwart lacks. It never lowers a role or removes an alias.
- `--apply` writes every secret again, because Stalwart doesn't return them. A line reading `unchanged` means no other field differs.
- It aborts before writing if an SQL account has no matching Stalwart User or an alias is on a domain Stalwart doesn't host.

## Deployment

- **Container Image**: `harbor.vaderrp.com/operinko-labs/stalwart-users`
- **CI/CD**: GitHub Actions builds the image on pushes to `main` and tags. Releases are triggered by tags.
- **SPA Deployment**: The SPA is packaged as a zip file in GitHub releases and should be registered in Stalwart. See [Stalwart app registration](docs/stalwart-app-registration.md) for details.

## License

Unlicensed
