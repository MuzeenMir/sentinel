# SENTINEL Setup Guide

Complete setup guide for SENTINEL Security Platform.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Configuration](#configuration)
4. [Running the Platform](#running-the-platform)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Production Deployment](#production-deployment)

## Prerequisites

### Required Software

- **Docker** 20.10 or higher
  - Installation: https://docs.docker.com/get-docker/
- **Docker Compose** 2.0 or higher
  - Usually included with Docker Desktop
  - Verify: `docker compose version`

### Optional (for Development)

- **Node.js** 18+ and **npm** 9+
  - Installation: https://nodejs.org/
- **Python** 3.11+ (for local backend development)
- **Make** (for convenience commands)
  - Windows: Install via Chocolatey or use Git Bash
  - Mac/Linux: Usually pre-installed

### System Requirements

**Minimum (Development):**
- CPU: 2 cores
- RAM: 4GB
- Disk: 10GB free space

**Recommended (Production):**
- CPU: 4+ cores
- RAM: 8GB+
- Disk: 50GB+ SSD
- Network: Stable internet connection

## Initial Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/MuzeenMir/sentinel.git
cd sentinel/sentinel-core
```

### Step 2: Run Setup Script

```bash
make setup
```

This will:
- Copy `sentinelenv.example` to `sentinelenv`
- Copy `frontend/admin-console/.env.example` to `frontend/admin-console/.env`
- Install frontend dependencies

### Step 3: Configure Environment

Edit `sentinelenv` file:

```bash
# Generate a secure JWT secret key
openssl rand -hex 32

# Edit sentinelenv
nano sentinelenv  # or use your preferred editor
```

**Critical Settings:**

```bash
# REQUIRED: Strong random JWT secret (minimum 32 characters)
JWT_SECRET_KEY=<paste-generated-key-here>

# REQUIRED: Admin credentials (change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<choose-strong-password>
ADMIN_EMAIL=admin@yourdomain.com

# Optional: Database password (change in production)
POSTGRES_PASSWORD=<strong-password>
```

### Step 4: Start Services

```bash
# Start all backend services
make up

# Or manually:
docker compose --env-file sentinelenv up -d
```

Wait for services to be healthy (30-60 seconds):

```bash
# Check health
make health

# Or watch logs
make logs
```

### Step 5: Start Frontend

In a new terminal:

```bash
make dev-frontend

# Or manually:
cd frontend/admin-console
npm run dev
```

## Configuration

### Environment Variables

#### Backend (`sentinelenv`)

See `.env.example` for all available options.

**Security:**
- `JWT_SECRET_KEY`: Must be a strong random string (min 32 chars)
- `ADMIN_PASSWORD`: Strong password for initial admin user
- `POSTGRES_PASSWORD`: Database password

**Service URLs:**
- Automatically configured for Docker Compose
- Change only if using external services

**AI Engine:**
- `CONFIDENCE_THRESHOLD`: Detection confidence (0.0-1.0, default: 0.85)
- `BATCH_SIZE`: Processing batch size (default: 1000)

#### Frontend (`frontend/admin-console/.env`)

```bash
# API Gateway URL
VITE_API_URL=http://localhost:8080

# Environment
VITE_ENV=development
```

### Docker Compose Configuration

Edit `docker-compose.yml` to:
- Change port mappings
- Adjust resource limits
- Add volume mounts for development

For production overrides, use `docker-compose.prod.yml`.

## Running the Platform

### Development Mode

**Backend:**
```bash
make up          # Start all services
make logs        # View logs
make restart     # Restart services
```

**Frontend:**
```bash
make dev-frontend  # Start dev server with hot-reload
```

Access:
- Frontend: http://localhost:3000
- API Gateway: http://localhost:8080
- API Health: http://localhost:8080/health

### Production Mode

```bash
# Use production configuration
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file sentinelenv up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

## Verification

### 1. Check Service Health

```bash
make health
```

Expected output:
- API Gateway: `{"status": "healthy", ...}`
- Auth Service: `{"status": "healthy", ...}`

### 2. Test Authentication

```bash
# Login via API
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'
```

Should return:
```json
{
  "access_token": "...",
  "user": {...},
  "expires_in": 86400
}
```

### 3. Access Admin Console

1. Open http://localhost:3000
2. Login with credentials from `sentinelenv`
3. Verify dashboard loads

### 4. Test API Endpoints

```bash
# Get token first
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}' | jq -r .access_token)

# Test protected endpoint
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/threats
```

## Troubleshooting

### Services Won't Start

**Check Docker:**
```bash
docker ps
docker compose ps
```

**Check Ports:**
```bash
# Linux/Mac
netstat -an | grep -E '8080|5000|5432|6379'

# Windows
netstat -an | findstr "8080 5000 5432 6379"
```

**View Logs:**
```bash
make logs
# Or specific service:
docker compose logs -f api-gateway
docker compose logs -f auth-service
docker compose logs -f postgres
```

### Database Connection Errors

**Wait for PostgreSQL:**
```bash
# Check if database is ready
docker compose exec postgres pg_isready -U sentinel
```

**Reset Database:**
```bash
# WARNING: This deletes all data!
docker compose down -v
docker compose --env-file sentinelenv up -d postgres
# Wait 30 seconds, then start other services
docker compose --env-file sentinelenv up -d
```

### Frontend Can't Connect to API

1. **Verify API Gateway is running:**
   ```bash
   curl http://localhost:8080/health
   ```

2. **Check CORS configuration** in `backend/api-gateway/app.py`

3. **Verify environment variable:**
   ```bash
   cat frontend/admin-console/.env
   # Should have: VITE_API_URL=http://localhost:8080
   ```

4. **Check browser console** for specific errors

### Authentication Issues

**Token Expired:**
- Tokens expire after 24 hours
- Re-login to get new token

**Invalid Credentials:**
- Verify username/password in `sentinelenv`
- Check admin user was created:
  ```bash
  docker compose logs auth-service | grep "Created initial admin"
  ```

**Token Verification Fails:**
- Ensure `JWT_SECRET_KEY` is the same across restarts
- Check token format: `Bearer <token>`

### Performance Issues

**High Memory Usage:**
- Reduce `BATCH_SIZE` in `sentinelenv`
- Limit AI Engine memory in `docker-compose.yml`

**Slow Responses:**
- Check Redis is running: `docker compose ps redis`
- Verify Kafka is healthy
- Check database connection pool settings

## Production Deployment

### Security Checklist

- [ ] Change all default passwords
- [ ] Use strong `JWT_SECRET_KEY` (32+ characters)
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Enable log aggregation
- [ ] Configure backup strategy
- [ ] Review and restrict network access
- [ ] Use secrets management (not plain env files)
- [ ] Enable rate limiting
- [ ] Configure CORS properly
- [ ] Set up health checks and auto-restart

### Recommended Production Setup

1. **Use Docker Compose Production Override:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

2. **Use External Services:**
   - Managed PostgreSQL (AWS RDS, Azure Database)
   - Managed Redis (AWS ElastiCache, Azure Cache)
   - Managed Kafka (AWS MSK, Confluent Cloud)

3. **Set Up Monitoring:**
   - Prometheus + Grafana
   - ELK Stack for logs
   - Application Performance Monitoring (APM)

4. **Configure Backups:**
   - Database backups (daily)
   - Configuration backups
   - Model backups

5. **Use Reverse Proxy:**
   - Nginx or Traefik
   - SSL/TLS termination
   - Load balancing

### Scaling

**Horizontal Scaling:**
- Run multiple API Gateway instances behind load balancer
- Scale AI Engine based on load
- Use Redis Cluster for high availability

**Vertical Scaling:**
- Increase resources in `docker-compose.prod.yml`
- Adjust worker counts in Dockerfiles

## Next Steps

- Read [API Documentation](docs/API.md)
- Review [Architecture](docs/architecture.md)
- Check [Security Guidelines](docs/security.md)
- Explore [ML Models](docs/ml-models.md)

## Support

- **Documentation:** See `docs/` directory
- **Issues:** GitHub Issues
- **Security:** security@sentinel.example.com
