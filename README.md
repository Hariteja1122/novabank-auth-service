# novabank-auth-service

Login, registration, customer profile and customer administration for NovaBank.
Issues the HS256 JWT that the gateway and every other service validate locally.

| | |
|---|---|
| Port | 8081 (Cloud Run: 8080 via `PORT`) |
| Db2 schema | `NB_AUTH` (table `USERS`) |
| Calls | account-service `/internal/accounts` to open a checking account on sign up |
| Swagger (local/dev) | http://localhost:8081/swagger-ui.html |

## Endpoints

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | public | Email + password, returns `{token, expiresInSeconds, user}` |
| POST | `/api/auth/register` | public | Creates a CUSTOMER and opens a checking account |
| GET | `/api/auth/me` | any user | Current profile |
| PUT | `/api/auth/me` | any user | Update name and phone |
| POST | `/api/auth/change-password` | any user | Change own password |
| GET | `/api/admin/users?role=&status=&q=&page=&size=` | ADMIN | Search customers |
| GET | `/api/admin/users/summary` | ADMIN | Counts for the admin dashboard |
| GET | `/api/admin/users/{id}` | ADMIN | Customer detail |
| PATCH | `/api/admin/users/{id}/status` | ADMIN | Lock or unlock a customer `{status: LOCKED/ACTIVE}` |

## Run

```bash
# Everything (Db2 + all services + UI) from novabank-platform:
../novabank-platform/dev.sh up

# Just this service from IntelliJ: start Db2 first, then use the "AuthService (local)" run config
../novabank-platform/dev.sh db
```

## Configuration

| Variable | Local default | Notes |
|---|---|---|
| `SPRING_PROFILES_ACTIVE` | `local` | `local`, `dev`, `preprod` |
| `DB_HOST` / `DB_PORT` / `DB_NAME` | `localhost` / `50000` / `NOVABANK` | |
| `DB_USER` / `DB_PASSWORD` | `db2inst1` / `NovaBank2026` | Secret Manager in GCP |
| `JWT_SECRET` | local value | Same value in every service |
| `INTERNAL_API_KEY` | `local-internal-key` | Same value in auth, account, transaction |
| `ACCOUNT_SERVICE_URL` | `http://localhost:8082` | |

Environment definitions: `src/main/resources/application-{local,dev,preprod}.yml` and
`deploy/environments/{dev,preprod}.yaml` (Cloud Run).
