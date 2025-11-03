# EQEQO Auth API

Centralized authentication and authorization service for the **Eqeqo** ecosystem.
Handles token issuance, validation, and access control for all other APIs.

---

## ⚙️ Setup

```bash
psql -U postgres -f db/run_all.sql
cargo run
```

Server default: `http://127.0.0.1:7878`

Environment:
```
DATABASE_URL=postgres://USER:PASSWORD@HOST/auth_api
SERVER_PORT=7878
TOKEN_TTL_SECONDS=300
TOKEN_RENEW_THRESHOLD_SECONDS=30
```

---

## 🧩 Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| **POST** | `/auth/login` | Generate a new token for valid user |
| **POST** | `/auth/logout` | Revoke token (delete from cache) |
| **GET** | `/auth/profile` | Validate token and return user payload (renews if valid) |
| **POST** | `/check-token` | Validate token from another API (atomic renewal logic) |
| **GET** | `/users` | List users |
| **POST** | `/users` | Create new user |
| **PUT** | `/users/{id}` | Update user |
| **DELETE** | `/users/{id}` | Disable or delete user |
| **GET** | `/roles` | List roles |
| **POST** | `/roles` | Create role |
| **GET** | `/permissions` | List permissions |
| **POST** | `/permissions` | Create permission |
| **POST** | `/role-permissions` | Assign permission to role |
| **POST** | `/service-roles` | Assign role to service |
| **POST** | `/person-service-roles` | Assign role to person in a service |

---

## 🗃️ Database (add directly to current schema)

```sql
CREATE TABLE auth.tokens_cache (
  token TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  modified_at NUMERIC NOT NULL
);
CREATE INDEX idx_auth_tokens_modified_at ON auth.tokens_cache(modified_at);
```

---

## 🔁 Token logic
- Generated at login (`hash(secret + random + timestamp)`).
- Stored in `auth.tokens_cache` with `payload` and `modified_at`.
- Renewed automatically if not expired (`TTL=5min`, threshold=30s).
- Removed on logout or user deletion.

---

## 🔐 Token header
All requests must include:

```
token: <token>
```

No tokens in URLs.

---

## 🧭 Use case diagram (visible on GitHub)

```mermaid
sequenceDiagram
  participant F as Frontend
  participant A as Auth API
  participant S as Stock API
  participant DB as Auth DB

  F->>A: POST /auth/login (user, pass)
  A->>DB: Validate user / generate token
  DB-->>A: token, payload
  A-->>F: {token, expires_at}

  F->>S: GET /stock/items\nHeader: token
  S->>A: POST /check-token (token)
  A->>DB: SELECT + conditional UPDATE modified_at
  DB-->>A: payload or 401
  A-->>S: valid payload
  S-->>F: authorized data
```

---

## 🧱 Security & cache
- Tokens stored centrally in DB (no Redis needed).
- Short TTL (2–5 min).
- Conditional atomic renewal to prevent DB contention.
- Revocation: delete from table.
- Logs: minimal (token, endpoint, ts, ip).

---

MIT © Eqeqo
