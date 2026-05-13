# Stalwart application registration

This is a one-time manual step to register the SPA in Stalwart after the sidecar is deployed and the first GitHub release is published.

## Prerequisites

- Stalwart sidecar deployed (via homeops HelmRelease)
- First GitHub release created (tag v0.1.0 or later) with stalwart-users-ui.zip artifact
- Admin access to Stalwart WebUI

## Steps

1. Navigate to **Stalwart Admin → Settings → Web Applications** at `https://stalwart-admin.vaderrp.com`
2. Click **Create Application**
3. Fill in the fields:
   - **Description**: `Mail User Management`
   - **Resource URL**: `https://github.com/operinko-labs/stalwart-users/releases/latest/download/stalwart-users-ui.zip`
   - **URL Prefix**: `/manage/users`
   - **Enabled**: `true`
   - **Auto Update Frequency**: `1d`
   - **Unpack Directory**: `user-management`
4. Click **Save**

## How it works

Stalwart downloads the zip from the Resource URL, unpacks it into the data directory under `user-management/`, and serves the SPA at `/manage/users/`. The `<base href="/">` tag in `index.html` is rewritten by Stalwart to match the URL prefix (`/manage/users/`).

The SPA's `fetchAPI()` detects it's running under `/manage/users` and sets `API_BASE` to `../api`, so API calls go to `/manage/api/accounts` etc., which the HTTPRoute forwards to the sidecar container on port 3000.

Configuration is persisted in Stalwart's database and survives pod restarts.

Auto-update checks for new zip content daily. Just push a new tag to publish an updated SPA.

## Verification

After saving, navigate to `https://stalwart-admin.vaderrp.com/manage/users/` and confirm:
- The login page loads (asking for a Bearer token)
- After entering a valid admin token, the Accounts tab shows existing accounts

## Reference

- [Stalwart Application object reference](https://stalw.art/docs/ref/object/application/)
