#!/bin/bash

# Smart Contract Platform Deployment Script
# This script automates the deployment process for different environments

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="development"
SKIP_DEPS=false
SKIP_DB=false
SKIP_TESTS=false
VERBOSE=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy the Smart Contract Platform

Options:
    -e, --environment ENV    Deployment environment (development|staging|production)
    -s, --skip-deps         Skip dependency installation
    -d, --skip-db           Skip database setup
    -t, --skip-tests        Skip running tests
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message

Examples:
    $0                                    # Deploy to development
    $0 -e production                      # Deploy to production
    $0 -e staging --skip-tests           # Deploy to staging without tests
    $0 --skip-deps --skip-db             # Quick deployment

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -s|--skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        -d|--skip-db)
            SKIP_DB=true
            shift
            ;;
        -t|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
    print_error "Invalid environment: $ENVIRONMENT"
    print_error "Must be one of: development, staging, production"
    exit 1
fi

# Set verbose mode
if [[ "$VERBOSE" == "true" ]]; then
    set -x
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

print_status "Starting deployment for environment: $ENVIRONMENT"
print_status "Project directory: $PROJECT_DIR"

# Change to project directory
cd "$PROJECT_DIR"

# Check if we're in the right directory
if [[ ! -f "main.py" ]]; then
    print_error "main.py not found. Are you in the correct directory?"
    exit 1
fi

# Load environment-specific configuration
ENV_FILE=".env.$ENVIRONMENT"
if [[ -f "$ENV_FILE" ]]; then
    print_status "Loading environment configuration from $ENV_FILE"
    export $(grep -v '^#' "$ENV_FILE" | xargs)
else
    print_warning "Environment file $ENV_FILE not found, using defaults"
fi

# Check Python version
print_status "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 8 ]]; then
    print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

print_success "Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [[ ! -d "venv" ]]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
if [[ "$SKIP_DEPS" != "true" ]]; then
    print_status "Installing/updating dependencies..."
    pip install --upgrade pip
    
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    else
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Install development dependencies for non-production environments
    if [[ "$ENVIRONMENT" != "production" && -f "requirements-dev.txt" ]]; then
        print_status "Installing development dependencies..."
        pip install -r requirements-dev.txt
    fi
    
    print_success "Dependencies installed successfully"
else
    print_warning "Skipping dependency installation"
fi

# Database setup
if [[ "$SKIP_DB" != "true" ]]; then
    print_status "Setting up database..."
    
    # Check if database migration script exists
    if [[ -f "scripts/migrate.py" ]]; then
        python scripts/migrate.py
    else
        print_warning "No migration script found, skipping database setup"
    fi
    
    print_success "Database setup completed"
else
    print_warning "Skipping database setup"
fi

# Run tests
if [[ "$SKIP_TESTS" != "true" && "$ENVIRONMENT" != "production" ]]; then
    print_status "Running tests..."
    
    if command -v pytest &> /dev/null; then
        if [[ -d "tests" ]]; then
            pytest tests/ -v
            print_success "All tests passed"
        else
            print_warning "No tests directory found, skipping tests"
        fi
    else
        print_warning "pytest not found, skipping tests"
    fi
else
    print_warning "Skipping tests"
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p data
mkdir -p static

# Set permissions
if [[ "$ENVIRONMENT" == "production" ]]; then
    print_status "Setting production permissions..."
    chmod -R 755 .
    chmod -R 644 logs/
fi

# Environment-specific deployment steps
case $ENVIRONMENT in
    "development")
        print_status "Development deployment completed"
        print_status "You can start the application with: python main.py"
        ;;
    "staging")
        print_status "Staging deployment"
        # Add staging-specific steps here
        ;;
    "production")
        print_status "Production deployment"
        
        # Check if running as root (not recommended)
        if [[ $EUID -eq 0 ]]; then
            print_warning "Running as root is not recommended for production"
        fi
        
        # Create systemd service file if it doesn't exist
        if [[ ! -f "/etc/systemd/system/smartcontract.service" ]]; then
            print_status "Creating systemd service file..."
            sudo tee /etc/systemd/system/smartcontract.service > /dev/null << EOF
[Unit]
Description=Smart Contract Platform
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
ExecStart=$PROJECT_DIR/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
            
            sudo systemctl daemon-reload
            sudo systemctl enable smartcontract
            print_success "Systemd service created and enabled"
        fi
        
        # Restart service
        print_status "Restarting service..."
        sudo systemctl restart smartcontract
        
        # Check service status
        if sudo systemctl is-active --quiet smartcontract; then
            print_success "Service is running"
        else
            print_error "Service failed to start"
            sudo systemctl status smartcontract
            exit 1
        fi
        ;;
esac

# Health check
print_status "Performing health check..."
sleep 5  # Give the service time to start

# Try to connect to the API
API_PORT=${API_PORT:-5000}
if command -v curl &> /dev/null; then
    if curl -f -s "http://localhost:$API_PORT/api/health" > /dev/null; then
        print_success "Health check passed - API is responding"
    else
        print_warning "Health check failed - API may not be ready yet"
    fi
else
    print_warning "curl not found, skipping health check"
fi

# Display deployment summary
print_success "\n=== Deployment Summary ==="
print_success "Environment: $ENVIRONMENT"
print_success "Python version: $PYTHON_VERSION"
print_success "Project directory: $PROJECT_DIR"
print_success "API port: $API_PORT"

if [[ "$ENVIRONMENT" == "development" ]]; then
    print_success "\nTo start the application:"
    print_success "  cd $PROJECT_DIR"
    print_success "  source venv/bin/activate"
    print_success "  python main.py"
elif [[ "$ENVIRONMENT" == "production" ]]; then
    print_success "\nService management:"
    print_success "  sudo systemctl start smartcontract"
    print_success "  sudo systemctl stop smartcontract"
    print_success "  sudo systemctl restart smartcontract"
    print_success "  sudo systemctl status smartcontract"
fi

print_success "\nAPI endpoints:"
print_success "  Health: http://localhost:$API_PORT/api/health"
print_success "  Blockchain: http://localhost:$API_PORT/api/blockchain/info"
print_success "  Documentation: http://localhost:$API_PORT/api/docs"

print_success "\nDeployment completed successfully!"