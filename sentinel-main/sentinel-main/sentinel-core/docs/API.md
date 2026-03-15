# SENTINEL API Documentation

## Base URL

- Development: `http://localhost:8080`
- Production: Configure via `VITE_API_URL` environment variable

## Authentication

Most endpoints require authentication via JWT Bearer token.

### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@sentinel.local",
    "role": "admin"
  },
  "expires_in": 86400
}
```

### Using the Token

Include the token in the Authorization header:

```http
Authorization: Bearer <access_token>
```

## Endpoints

### Health Check

```http
GET /health
```

Returns system health status and request statistics.

### Threats

#### Get All Threats

```http
GET /api/v1/threats
Authorization: Bearer <token>
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Items per page (default: 10)
- `severity` (optional): Filter by severity (critical, high, medium, low)

**Response:**
```json
{
  "data": {
    "items": [
      {
        "id": 1,
        "type": "DDoS Attack",
        "severity": "critical",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "status": "new",
        "timestamp": "2024-01-28T10:30:00Z"
      }
    ],
    "total": 100,
    "pages": 10,
    "current_page": 1
  }
}
```

#### Get Threat by ID

```http
GET /api/v1/threats/{id}
Authorization: Bearer <token>
```

### Policies

#### Get All Policies

```http
GET /api/v1/policies
Authorization: Bearer <token>
```

#### Create Policy

```http
POST /api/v1/policies
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Block SSH Brute Force",
  "action": "DENY",
  "source": "0.0.0.0/0",
  "destination": "*:22"
}
```

### Statistics

#### Get Dashboard Statistics

```http
GET /api/v1/statistics
Authorization: Bearer <token>
```

**Response:**
```json
{
  "data": {
    "totalThreats": 1247,
    "blockedThreats": 1189,
    "activePolicies": 42,
    "complianceScore": 94,
    "system_health": "healthy"
  }
}
```

## Error Responses

All errors follow this format:

```json
{
  "error": "Error type",
  "message": "Human-readable error message"
}
```

### Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error
- `503` - Service Unavailable

## Rate Limiting

- Default: 200 requests per hour per IP
- Some endpoints may have stricter limits
- Rate limit headers:
  - `X-RateLimit-Limit`: Maximum requests allowed
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Time when limit resets

## Best Practices

1. **Always use HTTPS in production**
2. **Store tokens securely** - Never expose tokens in client-side code
3. **Handle token expiration** - Implement token refresh logic
4. **Use appropriate HTTP methods** - GET for retrieval, POST for creation, PUT for updates, DELETE for deletion
5. **Implement retry logic** - Handle transient failures gracefully
6. **Respect rate limits** - Implement exponential backoff

## SDK Examples

### JavaScript/TypeScript

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8080',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Login
const login = async (username: string, password: string) => {
  const response = await api.post('/api/v1/auth/login', {
    username,
    password,
  });
  localStorage.setItem('token', response.data.access_token);
  return response.data;
};

// Get threats
const getThreats = async () => {
  const response = await api.get('/api/v1/threats');
  return response.data;
};
```

### Python

```python
import requests

BASE_URL = "http://localhost:8080"

class SentinelAPI:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.token = None
    
    def login(self, username, password):
        response = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"username": username, "password": password}
        )
        self.token = response.json()["access_token"]
        return response.json()
    
    def get_threats(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(
            f"{self.base_url}/api/v1/threats",
            headers=headers
        )
        return response.json()
```
