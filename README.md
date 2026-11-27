## Database schema

Auth stores user accounts and refresh tokens in PostgreSQL. User IDs are UUIDs, and timestamps use `timestamptz`. Atelier uses these user IDs for organization admin and gym staff assignments.

| Table | Non-nullable fields | Nullable fields |
| --- | --- | --- |
| `users` | `id` (PK), `username` (unique), `password_hash`, `created_at`, `updated_at` | `first_name`, `last_name`, `email` (unique when present), `email_verified_at`, `password_changed_at`, `disabled_at`, `last_login_at` |
| `refresh_tokens` | `token_hash` (PK), `user_id`, `expires_at` | — |

- Auth hashes passwords with BCrypt and stores refresh tokens as SHA-256 hashes.
- Each refresh token belongs to one user. Deleting the user also deletes their refresh tokens.
- Auth sets `created_at` and `updated_at` automatically. Successful password logins record `last_login_at`.
- A null `disabled_at` means the account is enabled. Disabled accounts cannot log in or refresh a session.

## API endpoints

Send request bodies as JSON. Login and refresh return a token pair and set `Cache-Control: no-store`.

| Method and path | Who can call it | Request body | Success response |
| --- | --- | --- | --- |
| `POST /api/auth/signup` | Anyone | `username`, `password`, optional `firstName`, `lastName`, and `email` | `201 Created` with `id` and `username`. |
| `POST /api/auth/login` | A user with valid credentials | `username`, `password` | `200 OK` with a new access token and refresh token. |
| `POST /api/auth/refresh` | A caller with a valid refresh token | `refreshToken` | `200 OK` with a new token pair. The submitted refresh token can no longer be used. |

- Usernames contain 3–64 ASCII letters, digits, periods, underscores, or hyphens. Signup passwords must be at least 8 characters and at most 72 UTF-8 bytes.
- Auth trims optional names and email and stores email in lowercase when supplied.
- A token pair returns `accessToken`, `tokenType` (`Bearer`), `expiresIn` (900 seconds), `refreshToken`, and `refreshExpiresIn` (604800 seconds).
- The access token is a signed JWT issued by `clmb-auth`. Its subject is the user's UUID, and `preferred_username` contains their username. Send it to Atelier as `Authorization: Bearer <accessToken>`.

### Error responses

| Status | When it applies |
| --- | --- |
| `400 Bad Request` | The JSON body is missing or malformed, or signup or login input is invalid. |
| `401 Unauthorized` | Login credentials are incorrect, the account is disabled, or the refresh token is missing, invalid, expired, or already used. |
| `409 Conflict` | The username or email is already in use. |
