# Quickstart Guide

## Prerequisites
- Python 3.11+
- Docker (for test target)
- Git

## Setup Steps

### 1. Clone and Setup Project
```bash
git clone <repository-url>
cd argus
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Setup Test Target
```bash
# Install OWASP Juice Shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Verify it's running
curl http://localhost:3000
```

### 3. Run Basic Scan
```bash
cd fathom
python main.py --url http://localhost:3000
```

Expected output: Check for missing security headers on the main page.

## Development Workflow

### Running Tests
```bash
pytest tests/
```

### Adding New Module
1. Create `modules/attack_modules/new_module.py`
2. Inherit from `BaseAttackModule`
3. Implement required methods
4. Add to `modules/__init__.py`

### Testing Against Juice Shop
- SQLi: `/rest/products/search?q=test`
- XSS: `/#/contact` (feedback form)
- Headers: Any endpoint

## Troubleshooting

### Docker Issues
```bash
# Stop and restart Juice Shop
docker stop juice-shop
docker rm juice-shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### Python Environment
```bash
# Recreate virtual environment
rm -rf .venv
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Scanner Not Finding Vulnerabilities
- Check if Juice Shop is running: `docker ps`
- Verify URL accessibility: `curl http://localhost:3000`
- Check scanner logs for errors
- Ensure modules are properly loaded

## Next Steps
- Run full scan: `python main.py --url http://localhost:3000 --full`
- View JSON output: `python main.py --url http://localhost:3000 --json`
- Customize config in `config/config.py`