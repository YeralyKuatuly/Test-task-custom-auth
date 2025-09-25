.PHONY: help setup setup-local clean build up down logs shell test

# Default target
help:
	@echo "Custom Auth System - Available Commands:"
	@echo ""
	@echo "Setup Commands:"
	@echo "  setup          - Setup project with Docker (recommended)"
	@echo "  setup-local    - Setup project for local development"
	@echo ""
	@echo "Docker Commands:"
	@echo "  build          - Build Docker containers"
	@echo "  up             - Start containers"
	@echo "  down           - Stop containers"
	@echo "  logs           - Show container logs"
	@echo "  shell          - Open shell in web container"
	@echo ""
	@echo "Development Commands:"
	@echo "  test           - Run tests"
	@echo "  clean          - Clean up containers and volumes"
	@echo ""
	@echo "Usage: make <command>"

# Setup project with Docker
setup:
	@echo "========================================"
	@echo "Custom Auth System - Linux/Mac Setup"
	@echo "========================================"
	@echo ""
	@if [ -f .env ]; then \
		echo ".env file already exists!"; \
		read -p "Do you want to overwrite it? (y/N): " overwrite; \
		if [ "$$overwrite" != "y" ] && [ "$$overwrite" != "Y" ]; then \
			echo "Setup cancelled."; \
			exit 0; \
		fi; \
	fi
	@echo "Creating .env file from template..."
	@cp env.example .env
	@echo "Generating random secret keys..."
	@python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(50))" > temp_secret.txt
	@python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(50))" > temp_jwt.txt
	@sed -i.bak "s/SECRET_KEY=.*/$$(cat temp_secret.txt)/" .env
	@sed -i.bak "s/JWT_SECRET_KEY=.*/$$(cat temp_jwt.txt)/" .env
	@rm -f temp_secret.txt temp_jwt.txt .env.bak
	@echo ""
	@echo "========================================"
	@echo "Setup completed successfully!"
	@echo "========================================"
	@echo ""
	@echo "Next steps:"
	@echo "1. Run: make up"
	@echo "2. Open: http://localhost:8000"
	@echo ""
	@echo "The .env file has been created with random secret keys."
	@echo "You can modify it if needed."

# Setup for local development
setup-local:
	@echo "Setting up for local development..."
	@if [ -f .env ]; then \
		echo ".env file already exists!"; \
		read -p "Do you want to overwrite it? (y/N): " overwrite; \
		if [ "$$overwrite" != "y" ] && [ "$$overwrite" != "Y" ]; then \
			echo "Setup cancelled."; \
			exit 0; \
		fi; \
	fi
	@cp env.example .env
	@echo "Configuring for local development..."
	@sed -i.bak 's/USE_SQLITE=False/USE_SQLITE=True/' .env
	@rm -f .env.bak
	@echo "Installing dependencies..."
	@python3 -m venv venv
	@. venv/bin/activate && pip install -r requirements.txt
	@echo "Running migrations..."
	@. venv/bin/activate && python manage.py migrate
	@echo "Setting up demo data..."
	@. venv/bin/activate && python manage.py setup_demo_data
	@echo ""
	@echo "Local setup completed!"
	@echo "To start the server: . venv/bin/activate && python manage.py runserver"

# Docker commands
build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

shell:
	docker-compose exec web bash

# Development commands
test:
	python manage.py test --settings=config.test_settings

# Clean up
clean:
	docker-compose down -v
	docker system prune -f
