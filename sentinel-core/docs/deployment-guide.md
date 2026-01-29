# SENTINEL Deployment Guide

## Prerequisites

- AWS Account with appropriate permissions
- Terraform >= 1.5.0
- Docker and Docker Compose
- AWS CLI configured
- Node.js >= 18 (for frontend)
- Python >= 3.10 (for backend services)

## Local Development Deployment

### 1. Clone and Setup

```bash
git clone https://github.com/MuzeenMir/sentinel.git
cd sentinel/sentinel-core
```

### 2. Environment Configuration

Create `sentinelenv` file:

```bash
# Database
DATABASE_URL=postgresql://sentinel:sentinel_password@localhost:5432/sentinel_db
POSTGRES_PASSWORD=sentinel_password

# Redis
REDIS_URL=redis://localhost:6379

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# JWT
JWT_SECRET_KEY=your-secret-key-change-in-production

# Services
AI_ENGINE_URL=http://localhost:5003
DRL_ENGINE_URL=http://localhost:5005
POLICY_SERVICE_URL=http://localhost:5004
```

### 3. Start Infrastructure Services

```bash
docker compose --env-file sentinelenv up -d postgres redis zookeeper kafka
```

### 4. Start Application Services

```bash
docker compose --env-file sentinelenv up -d auth-service api-gateway data-collector alert-service ai-engine
```

### 5. Start Frontend (Development)

```bash
cd frontend/admin-console
npm install
npm run dev
```

## AWS Production Deployment

### 1. Initialize Terraform

```bash
cd infrastructure/terraform
terraform init
```

### 2. Configure Variables

Create `terraform.tfvars`:

```hcl
aws_region = "us-east-1"
environment = "prod"
vpc_cidr = "10.0.0.0/16"
db_password = "your-secure-password"
db_instance_class = "db.t3.medium"
msk_instance_type = "kafka.m5.large"
sagemaker_instance_type = "ml.m5.xlarge"
```

### 3. Plan and Apply

```bash
terraform plan -out=tfplan
terraform apply tfplan
```

### 4. Build and Push Docker Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

# Build and push each service
for service in api-gateway auth-service alert-service data-collector ai-engine drl-engine policy-orchestrator xai-service compliance-engine; do
  docker build -t sentinel-$service ./backend/$service
  docker tag sentinel-$service:latest <account>.dkr.ecr.us-east-1.amazonaws.com/prod-sentinel-$service:latest
  docker push <account>.dkr.ecr.us-east-1.amazonaws.com/prod-sentinel-$service:latest
done
```

### 5. Deploy ECS Services

ECS services are created by Terraform. Update task definitions to use the pushed images.

### 6. Configure DNS and Load Balancer

1. Create Route53 hosted zone for your domain
2. Create alias record pointing to the ALB
3. Configure HTTPS listener with ACM certificate

## Kubernetes Deployment (Alternative)

### 1. Create EKS Cluster

```bash
eksctl create cluster --name sentinel-cluster --region us-east-1 --nodegroup-name standard-workers --node-type m5.large --nodes 3
```

### 2. Apply Kubernetes Manifests

```bash
kubectl apply -f infrastructure/kubernetes/
```

## Post-Deployment Steps

### 1. Initialize Database

```bash
docker exec -it sentinel-postgres psql -U sentinel -d sentinel_db -f /docker-entrypoint-initdb.d/init.sql
```

### 2. Create Admin User

```bash
curl -X POST http://localhost:5000/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "email": "admin@example.com", "password": "secure-password", "role": "admin"}'
```

### 3. Verify Services

```bash
# Check all services are healthy
curl http://localhost:8080/health
curl http://localhost:5003/health  # AI Engine
curl http://localhost:5005/health  # DRL Engine
curl http://localhost:5004/health  # Policy Orchestrator
```

### 4. Train Initial Models (Optional)

```bash
# Upload training data to S3
aws s3 cp training_data/ s3://sentinel-ml-models/training/ --recursive

# Trigger SageMaker training job
aws sagemaker create-training-job --training-job-name sentinel-initial-training ...
```

## Monitoring and Observability

### CloudWatch Dashboards

Access CloudWatch for:
- ECS service metrics
- MSK cluster metrics
- RDS performance insights
- Application logs

### Prometheus/Grafana (Optional)

```bash
helm install prometheus prometheus-community/prometheus
helm install grafana grafana/grafana
```

## Scaling Considerations

| Component | Scaling Strategy |
|-----------|-----------------|
| API Gateway | Horizontal (ECS auto-scaling) |
| AI Engine | Horizontal + GPU instances for inference |
| DRL Engine | Horizontal |
| Kafka | Add brokers, increase partitions |
| PostgreSQL | Vertical (larger instance) + Read replicas |
| Redis | Cluster mode for high throughput |

## Backup and Recovery

### Database Backups

- RDS automated backups enabled (7-day retention)
- Manual snapshots before major changes

### Model Backups

- S3 versioning enabled for model artifacts
- Retain last 5 model versions

## Troubleshooting

### Common Issues

1. **Services can't connect to Kafka**
   - Check security group rules
   - Verify MSK bootstrap servers in environment variables

2. **AI Engine slow response**
   - Check model loading status
   - Increase memory allocation
   - Consider GPU instances

3. **DRL decisions not applying**
   - Verify Policy Orchestrator connectivity
   - Check firewall vendor credentials
   - Review policy validation logs
