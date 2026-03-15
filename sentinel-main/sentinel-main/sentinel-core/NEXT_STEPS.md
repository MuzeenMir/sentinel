# Next steps and access

## Access and credentials

| Step | Action |
|------|--------|
| 1 | Open **http://localhost:3000** (or your host:3000 if using another machine). |
| 2 | **Admin login:** Use username **`admin`** and password **`Admin@123!SecurePassword`** (from `sentinel_env`). |
| 3 | **Demo mode:** With `VITE_DEMO_AUTH=true`, the app auto-attempts login with `demo` / `demo-token`. If that fails (e.g. backend returns 500), the **client-side demo bypass** activates and the dashboard loads with a placeholder user—no backend demo user required. |
| 4 | Verify services: `docker compose --env-file sentinel_env ps` and **http://localhost:8080/health** for the API gateway. |
| 5 | Optional local frontend dev: `cd frontend/admin-console && npm install && npm run dev`; set `VITE_API_URL=http://localhost:8080` in `.env` if needed. |

---

## Implemented: client-side demo bypass (Option B)

When demo mode is on and the login request fails (500 or network error), the app now calls `setDemoBypass()` so the user is treated as authenticated and the dashboard loads with a placeholder user. No backend demo user is required. The API interceptor does not log out on 401 when the token is the demo-bypass token, and the request interceptor does not send the demo-bypass token as a Bearer header.

---

## Optional improvements

- **Loading state for demo login:** Show a spinner until the demo login attempt (or bypass) completes.
- **Option A – Demo user in DB:** To have real demo credentials work against the API, add a user `demo` / `demo-token` via auth-service or DB seed.
