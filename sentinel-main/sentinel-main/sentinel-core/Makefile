.PHONY: help build up down restart logs clean test install

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	cd frontend/admin-console && npm install
	@echo "Frontend dependencies installed"

build: ## Build all Docker images
	docker compose build

up: ## Start all services
	docker compose --env-file sentinelenv up -d

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

logs: ## Show logs from all services
	docker compose logs -f

logs-api: ## Show API Gateway logs
	docker compose logs -f api-gateway

logs-auth: ## Show Auth Service logs
	docker compose logs -f auth-service

clean: ## Remove all containers, volumes, and images
	docker compose down -v --rmi all

test: ## Run tests
	@echo "Running tests..."
	# Add test commands here

dev-frontend: ## Start frontend development server
	cd frontend/admin-console && npm run dev

dev-backend: ## Start backend services in development mode
	docker compose --env-file sentinelenv up -d postgres redis kafka
	@echo "Backend services started. Start individual services manually for development."

setup: ## Initial setup - copy env files and install dependencies
	@if [ ! -f sentinelenv ]; then \
		cp sentinelenv.example sentinelenv; \
		echo "Created sentinelenv file. Please update it with your values."; \
	fi
	@if [ ! -f frontend/admin-console/.env ]; then \
		cp frontend/admin-console/.env.example frontend/admin-console/.env; \
		echo "Created frontend/.env file."; \
	fi
	$(MAKE) install
	@echo "Setup complete!"

health: ## Check health of all services
	@echo "Checking service health..."
	@curl -s http://localhost:8080/health | jq . || echo "API Gateway: Not responding"
	@curl -s http://localhost:5000/health | jq . || echo "Auth Service: Not responding"
