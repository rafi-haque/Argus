# Contributing to Argus

Thank you for your interest in contributing to Argus! This document provides guidelines and instructions for contributing.

## 🎯 Code of Conduct

By participating in this project, you agree to:
- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other contributors

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Git
- Basic understanding of web security concepts

### Development Setup

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/argus.git

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy
```

## 📝 How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check if the bug has already been reported
2. Update to the latest version and test again
3. Collect relevant information (OS, Python version, error messages)

Create a bug report with:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Screenshots if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:
- Use a clear, descriptive title
- Provide detailed description of the proposed functionality
- Explain why this enhancement would be useful
- List any alternative solutions considered

### Pull Requests

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make Your Changes**
   - Follow the coding standards (see below)
   - Write or update tests
   - Update documentation if needed
   - Keep commits atomic and well-described

3. **Test Your Changes**
   ```bash
   # Run tests
   pytest
   
   # Check code style
   black argus/
   flake8 argus/
   mypy argus/
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "type: brief description"
   ```
   
   Commit types:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Code style changes (formatting)
   - `refactor:` Code refactoring
   - `test:` Test additions or changes
   - `chore:` Build process or auxiliary tool changes

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Go to GitHub and create a pull request
   - Fill out the PR template completely
   - Link related issues
   - Wait for review

## 💻 Coding Standards

### Python Style

- Follow PEP 8
- Use Black for formatting (line length: 88)
- Use type hints where applicable
- Write docstrings for functions and classes

```python
def scan_target(url: str, policy: str = "standard") -> dict[str, Any]:
    """
    Scan a target URL for vulnerabilities.
    
    Args:
        url: Target URL to scan
        policy: Scan policy to use (default: "standard")
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        ValueError: If URL is invalid
    """
    pass
```

### Module Structure

New detection modules should follow this structure:

```python
"""
Module: module_name
Description: Brief description of what this module detects
"""

from typing import Any
from argus.http_utils import HTTPClient

class ModuleNameScanner:
    """Scanner for detecting specific vulnerability."""
    
    def __init__(self, client: HTTPClient):
        """Initialize the scanner."""
        self.client = client
        
    async def scan(self, url: str, parameter: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Scan for vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter information
            
        Returns:
            List of findings
        """
        findings = []
        # Implementation
        return findings
```

### Testing

- Write unit tests for new functionality
- Aim for >80% code coverage
- Use pytest fixtures for common setup
- Mock external dependencies

```python
import pytest
from argus.modules.your_module import YourScanner

@pytest.fixture
def scanner():
    """Create scanner instance."""
    return YourScanner(mock_client)

def test_scanner_detection(scanner):
    """Test vulnerability detection."""
    result = scanner.scan("http://example.com", {})
    assert len(result) > 0
```

### Documentation

- Update relevant documentation for changes
- Add docstrings to new functions/classes
- Include examples in docstrings
- Update README.md if adding major features

## 🏗️ Project Structure

```
argus/
├── argus/              # Core package
│   ├── modules/       # Detection modules (add new modules here)
│   ├── compliance/    # Compliance frameworks
│   ├── database/      # Database layer
│   └── config/        # Configuration files
├── tools/             # Utility scripts
├── tests/             # Test suite
│   ├── unit/         # Unit tests
│   └── integration/  # Integration tests
├── docs/              # Documentation
└── examples/          # Example files
```

## 🔍 Areas for Contribution

### High Priority
- New vulnerability detection modules
- Performance optimizations
- Test coverage improvements
- Documentation enhancements

### Good First Issues
- Bug fixes in existing modules
- Documentation improvements
- Code style consistency
- Adding type hints

### Advanced Contributions
- New compliance frameworks
- Advanced crawling techniques
- Machine learning for false positive reduction
- Distributed scanning architecture

## 🧪 Testing Guidelines

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/unit/test_http_utils.py

# With coverage
pytest --cov=argus --cov-report=html

# Verbose output
pytest -v
```

### Writing Tests

- Test file naming: `test_*.py`
- Test function naming: `test_*`
- Use descriptive test names
- One assertion per test when possible
- Use fixtures for common setup

## 📋 Checklist

Before submitting a PR, ensure:

- [ ] Code follows PEP 8 and passes `black` formatting
- [ ] All tests pass (`pytest`)
- [ ] Code coverage is maintained or improved
- [ ] Documentation is updated
- [ ] Commit messages are clear and follow conventions
- [ ] PR description explains the changes
- [ ] Related issues are linked

## 🤝 Review Process

1. Automated checks run (tests, linting)
2. Maintainer reviews code
3. Feedback is provided if needed
4. Changes are requested or approved
5. PR is merged into main branch

## 📞 Getting Help

- 💬 GitHub Discussions for questions
- 🐛 GitHub Issues for bugs
- 📧 Email maintainers for sensitive issues

## 📜 License

By contributing to Argus, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Argus! 🎉
