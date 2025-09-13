# Smart Contract Platform Deployment Guide

This guide provides comprehensive instructions for deploying the Smart Contract Platform in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Cloud Deployment](#cloud-deployment)
6. [Configuration](#configuration)
7. [Security Considerations](#security-considerations)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows 10+
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for production)
- **Storage**: Minimum 20GB free space (SSD recommended)
- **Network**: Stable internet connection for blockchain synchronization

### Required Software

```bash
# Python and pip
python3 --version  # Should be 3.8+
pip3 --version

# Git
git --version

# Optional but recommended
docker --version
docker-compose --version
```

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/smart-contract-platform.git
cd smart-contract-platform
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

### 4. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 5. Initialize Database

```bash
# Run database migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### 6. Start Development Server

```bash
# Start the full platform
python main.py

# Or start specific components
python main.py --api-only --port 8080
python main.py --blockchain-only
python main.py --oracle-only
```

### 7. Verify Installation

```bash
# Check API health
curl http://localhost:5000/api/health

# Check blockchain info
curl http://localhost:5000/api/blockchain/info

# Run tests
python -m pytest tests/
```

## Production Deployment

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv git nginx supervisor

# Create application user
sudo useradd -m -s /bin/bash smartcontract
sudo usermod -aG sudo smartcontract
```

### 2. Application Setup

```bash
# Switch to application user
sudo su - smartcontract

# Clone repository
git clone https://github.com/your-repo/smart-contract-platform.git
cd smart-contract-platform

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
```

### 3. Production Configuration

```bash
# Create production environment file
cp .env.example .env.production

# Edit production settings
nano .env.production
```

**Production Environment Variables:**

```bash
# Application
ENVIRONMENT=production
DEBUG=False
SECRET_KEY=your-super-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/smartcontract

# Redis (for caching and sessions)
REDIS_URL=redis://localhost:6379/0

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Blockchain
BLOCKCHAIN_NETWORK=mainnet
CONSENSUS_TYPE=pos
MINING_ENABLED=True

# Security
JWT_SECRET_KEY=your-jwt-secret-key
ENCRYPTION_KEY=your-encryption-key

# Oracle Configuration
ORACLE_ENABLED=True
PRICE_FEED_INTERVAL=60

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/smartcontract/app.log
```

### 4. Database Setup

```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE smartcontract;
CREATE USER smartcontract_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE smartcontract TO smartcontract_user;
\q

# Run migrations
python manage.py migrate
```

### 5. Web Server Configuration

**Nginx Configuration (`/etc/nginx/sites-available/smartcontract`):**

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static files
    location /static/ {
        alias /home/smartcontract/smart-contract-platform/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    location /api/ {
        limit_req zone=api burst=20 nodelay;
    }
}
```

**Enable the site:**

```bash
sudo ln -s /etc/nginx/sites-available/smartcontract /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Process Management

**Supervisor Configuration (`/etc/supervisor/conf.d/smartcontract.conf`):**

```ini
[program:smartcontract-api]
command=/home/smartcontract/smart-contract-platform/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 4 --timeout 120 api.wsgi:application
directory=/home/smartcontract/smart-contract-platform
user=smartcontract
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/smartcontract/api.log
stdout_logfile_maxbytes=100MB
stdout_logfile_backups=5

[program:smartcontract-blockchain]
command=/home/smartcontract/smart-contract-platform/venv/bin/python main.py --blockchain-only
directory=/home/smartcontract/smart-contract-platform
user=smartcontract
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/smartcontract/blockchain.log
stdout_logfile_maxbytes=100MB
stdout_logfile_backups=5

[program:smartcontract-oracle]
command=/home/smartcontract/smart-contract-platform/venv/bin/python main.py --oracle-only
directory=/home/smartcontract/smart-contract-platform
user=smartcontract
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/smartcontract/oracle.log
stdout_logfile_maxbytes=100MB
stdout_logfile_backups=5

[group:smartcontract]
programs=smartcontract-api,smartcontract-blockchain,smartcontract-oracle
```

**Start services:**

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start smartcontract:*
sudo supervisorctl status
```

## Docker Deployment

### 1. Dockerfile

```dockerfile
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Start application
CMD ["python", "main.py"]
```

### 2. Docker Compose

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/smartcontract
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=smartcontract
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    
  redis:
    image: redis:6-alpine
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - app
    restart: unless-stopped

volumes:
  postgres_data:
```

### 3. Deploy with Docker

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale services
docker-compose up -d --scale app=3

# Update services
docker-compose pull
docker-compose up -d
```

## Cloud Deployment

### AWS Deployment

#### 1. EC2 Instance Setup

```bash
# Launch EC2 instance (Ubuntu 20.04 LTS)
# Instance type: t3.medium or larger
# Security groups: Allow HTTP (80), HTTPS (443), SSH (22)

# Connect to instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Follow production deployment steps above
```

#### 2. RDS Database

```bash
# Create RDS PostgreSQL instance
# Update DATABASE_URL in environment variables
DATABASE_URL=postgresql://username:password@your-rds-endpoint:5432/smartcontract
```

#### 3. ElastiCache Redis

```bash
# Create ElastiCache Redis cluster
# Update REDIS_URL in environment variables
REDIS_URL=redis://your-elasticache-endpoint:6379/0
```

#### 4. Application Load Balancer

```bash
# Create ALB with SSL certificate
# Configure health checks: /api/health
# Set up auto-scaling group
```

### Google Cloud Platform

#### 1. Cloud Run Deployment

```bash
# Build and push container
gcloud builds submit --tag gcr.io/PROJECT_ID/smartcontract

# Deploy to Cloud Run
gcloud run deploy smartcontract \
  --image gcr.io/PROJECT_ID/smartcontract \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

#### 2. Cloud SQL

```bash
# Create Cloud SQL PostgreSQL instance
gcloud sql instances create smartcontract-db \
  --database-version=POSTGRES_13 \
  --tier=db-f1-micro \
  --region=us-central1
```

### Azure Deployment

#### 1. Container Instances

```bash
# Create resource group
az group create --name smartcontract-rg --location eastus

# Deploy container
az container create \
  --resource-group smartcontract-rg \
  --name smartcontract-app \
  --image your-registry/smartcontract:latest \
  --dns-name-label smartcontract-app \
  --ports 5000
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENVIRONMENT` | Deployment environment | `development` | No |
| `DEBUG` | Enable debug mode | `True` | No |
| `SECRET_KEY` | Application secret key | - | Yes |
| `DATABASE_URL` | Database connection URL | `sqlite:///app.db` | No |
| `REDIS_URL` | Redis connection URL | - | No |
| `API_HOST` | API server host | `127.0.0.1` | No |
| `API_PORT` | API server port | `5000` | No |
| `JWT_SECRET_KEY` | JWT signing key | - | Yes |
| `BLOCKCHAIN_NETWORK` | Blockchain network | `testnet` | No |
| `ORACLE_ENABLED` | Enable oracle services | `True` | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |

### Configuration Files

#### config/production.py

```python
import os
from .base import *

# Security
DEBUG = False
ALLOWED_HOSTS = ['your-domain.com', 'www.your-domain.com']
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Caching
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/smartcontract/app.log',
            'maxBytes': 100*1024*1024,  # 100MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['file'],
        'level': 'INFO',
    },
}
```

## Security Considerations

### 1. SSL/TLS Configuration

```bash
# Install Certbot for Let's Encrypt
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 2. Firewall Configuration

```bash
# Configure UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

### 3. Security Headers

Ensure your web server includes security headers:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

### 4. Database Security

```bash
# Secure PostgreSQL
sudo -u postgres psql
\password postgres  # Set strong password

# Edit pg_hba.conf to restrict access
sudo nano /etc/postgresql/13/main/pg_hba.conf
```

## Monitoring and Logging

### 1. Application Monitoring

```python
# Install monitoring tools
pip install prometheus-client grafana-api

# Add to requirements.txt
prometheus-client==0.14.1
grafana-api==1.0.3
```

### 2. Log Aggregation

```bash
# Install ELK Stack or use cloud services
# Configure log shipping
sudo apt install filebeat
```

### 3. Health Checks

```bash
# Create health check script
cat > /usr/local/bin/health-check.sh << 'EOF'
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/api/health)
if [ $response -eq 200 ]; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy (HTTP $response)"
    exit 1
fi
EOF

chmod +x /usr/local/bin/health-check.sh

# Add to crontab for monitoring
*/5 * * * * /usr/local/bin/health-check.sh
```

## Troubleshooting

### Common Issues

#### 1. Port Already in Use

```bash
# Find process using port
sudo lsof -i :5000

# Kill process
sudo kill -9 PID
```

#### 2. Database Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U smartcontract_user -d smartcontract
```

#### 3. Permission Issues

```bash
# Fix file permissions
sudo chown -R smartcontract:smartcontract /home/smartcontract/smart-contract-platform
sudo chmod -R 755 /home/smartcontract/smart-contract-platform
```

#### 4. Memory Issues

```bash
# Check memory usage
free -h
top

# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Log Analysis

```bash
# View application logs
sudo tail -f /var/log/smartcontract/app.log

# View nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# View system logs
sudo journalctl -u smartcontract-api -f
```

### Performance Tuning

```bash
# Optimize PostgreSQL
sudo nano /etc/postgresql/13/main/postgresql.conf

# Key settings:
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
```

## Backup and Recovery

### Database Backup

```bash
# Create backup script
cat > /usr/local/bin/backup-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

pg_dump -h localhost -U smartcontract_user smartcontract > $BACKUP_DIR/backup_$DATE.sql
gzip $BACKUP_DIR/backup_$DATE.sql

# Keep only last 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete
EOF

chmod +x /usr/local/bin/backup-db.sh

# Schedule daily backups
echo "0 2 * * * /usr/local/bin/backup-db.sh" | sudo crontab -
```

### Application Backup

```bash
# Backup application files
tar -czf /backups/app_$(date +%Y%m%d).tar.gz /home/smartcontract/smart-contract-platform
```

## Support

For deployment support:
- Documentation: [GitHub Repository](https://github.com/your-repo/smart-contract-platform)
- Issues: [GitHub Issues](https://github.com/your-repo/smart-contract-platform/issues)
- Community: [Discord Server](https://discord.gg/your-server)
- Email: support@smartcontractplatform.com