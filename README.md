# Insighta Labs+ — Backend

REST API for the Insighta Labs+ Profile Intelligence System. Serves both the CLI and web portal.

## System Architecture

```
insighta-cli  ──┐
                ├──► insighta-backend (Express + SQLite) ──► GitHub OAuth API
insighta-web  ──┘                                        ──► genderize.io / agify.io / nationalize.io
```

- **insighta-backend** — single source of truth. All business logic, auth, and data live here.
- **insighta-cli** — talks to the backend via Bearer token in `Authorization` header.
- **insighta-web** — talks to the backend via HTTP-only cookies, proxying all API calls server-side.

**Stack:** Node.js, Express, better-sqlite3, jsonwebtoken, csrf-csrf, morgan, express-rate-limit.

## Auth Flow

1. Client (CLI or web) calls `GET /api/v1/auth/github?interface=cli|web&redirect_uri=<uri>`.
2. Backend generates a PKCE `code_verifier` + `code_challenge` (SHA-256), stores them keyed by a random `state`, and returns the GitHub authorization URL.
3. User authorizes on GitHub. GitHub redirects to `redirect_uri` with `code` + `state`.
4. Client calls `GET /api/v1/auth/github/callback?code=&state=`.
5. Backend verifies `state`, retrieves the stored PKCE verifier, and exchanges the code with GitHub using `code_verifier`.
6. Backend fetches the GitHub user, upserts them in the DB, assigns role, and issues tokens:
   - **CLI**: returns `access_token` + `refresh_token` as JSON.
   - **Web**: sets `access_token` and `refresh_token` as HTTP-only cookies, then redirects to the web portal dashboard.

## Token Handling

| Token | TTL | Storage |
|---|---|---|
| Access token (JWT) | 15 minutes | CLI: `~/.insighta/credentials.json` / Web: HTTP-only cookie |
| Refresh token (JWT) | 7 days | Hashed (SHA-256) in `refresh_tokens` DB table |

- Refresh tokens are rotated on every use — old token is deleted, new pair issued.
- Refresh tokens are revoked on logout.
- The CLI checks token expiry before every request and refreshes automatically if within 60 seconds of expiry.

## Role Enforcement

Roles are assigned at first login:
- If the GitHub username is in the `ADMIN_USERS` env var → `admin`
- Otherwise → `analyst`

| Endpoint | analyst | admin |
|---|---|---|
| `GET /api/v1/profiles` | ✅ | ✅ |
| `POST /api/v1/profiles` | ✅ | ✅ |
| `GET /api/v1/profiles/:id` | ✅ | ✅ |
| `GET /api/v1/profiles/search` | ✅ | ✅ |
| `GET /api/v1/profiles/export` | ❌ | ✅ |
| `DELETE /api/v1/profiles/:id` | ❌ | ✅ |
| `GET /api/v1/users` | ❌ | ✅ |
| `PATCH /api/v1/users/:id/role` | ❌ | ✅ |

Enforced via `requireRole("admin")` middleware chained after `authenticate`.

## Natural Language Parsing

`GET /api/v1/profiles/search?q=<query>` parses free-text queries into structured filters using regex matching:

- **Gender**: detects `male`, `female`, `males`, `females`
- **Age group**: detects `children`, `teenagers`, `adults`, `seniors`, `young`
- **Age range**: detects `above N`, `below N`, `older than N`, `younger than N`, `between N and N`
- **Country**: detects `from <country>` or `in <country>` and maps to ISO country code

Example queries:
```
females above 30 from nigeria
young males in egypt
adults between 25 and 40
```

## API Reference

All routes are versioned under `/api/v1`.

### Auth
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/auth/github` | — | Initiate OAuth flow |
| GET | `/auth/github/callback` | — | OAuth callback |
| POST | `/auth/refresh` | — | Refresh access token |
| POST | `/auth/logout` | ✅ | Logout + revoke refresh token |
| GET | `/auth/me` | ✅ | Current user info |

### Profiles
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/profiles` | any | List with filters + pagination |
| POST | `/profiles` | any | Create profile |
| GET | `/profiles/search` | any | Natural language search |
| GET | `/profiles/export` | admin | Download CSV |
| GET | `/profiles/:id` | any | Get by ID |
| DELETE | `/profiles/:id` | admin | Delete profile |

### Users
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/users` | admin | List all users |
| PATCH | `/users/:id/role` | admin | Update user role |

### Pagination shape
```json
{
  "status": "success",
  "page": 1,
  "limit": 10,
  "total": 2026,
  "total_pages": 203,
  "has_next": true,
  "has_prev": false,
  "data": [...]
}
```

## Setup

```bash
npm install
cp .env.example .env
# Fill in .env with your values
npm start
```

### Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Server port (default: 3000) |
| `JWT_SECRET` | Secret for signing access tokens |
| `JWT_REFRESH_SECRET` | Secret for signing refresh tokens |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID (web) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret (web) |
| `GITHUB_CLI_CLIENT_ID` | GitHub OAuth App client ID (CLI) |
| `GITHUB_CLI_CLIENT_SECRET` | GitHub OAuth App client secret (CLI) |
| `ADMIN_USERS` | Comma-separated GitHub usernames with admin role |
| `WEB_ORIGIN` | Web portal origin for CORS (default: http://localhost:4000) |

### Seed the database

```bash
node src/seed.js /path/to/seed_profiles.json
```
