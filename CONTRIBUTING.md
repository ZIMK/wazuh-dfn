# Contributing to wazuh-dfn

Thank you for your interest in contributing to wazuh-dfn! This document provides guidelines and instructions for contributing to the project.

## Development Setup

1. Create a virtual environment:
```bash
python3.12 -m virtualenv venv
source venv/bin/activate
```

2. Install development dependencies:
```bash
pip install -e ".[dev]"
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep lines under 100 characters
- Use black for code formatting
- Use isort for import sorting

## Testing

1. Run the test suite:
```bash
pytest
```

2. Ensure test coverage:
```bash
pytest --cov=wazuh_dfn
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run the test suite
5. Update documentation if needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your fork (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests in the body

## Development Workflow

1. Pick an issue to work on or create a new one
2. Discuss the proposed changes in the issue
3. Fork and clone the repository
4. Create a new branch for your changes
5. Make your changes
6. Write or update tests
7. Update documentation
8. Submit a pull request

## Code Review Process

1. At least one maintainer must review and approve the changes
2. All automated checks must pass
3. Documentation must be updated if needed
4. Test coverage should not decrease

## Release Process

1. Update version in pyproject.toml
2. Update CHANGELOG.md
3. Create a new release tag
4. Build and publish to PyPI

## Setting Up Development Environment

### Prerequisites

- Python 3.12
- virtualenv
- git

### Installation Steps

1. Clone your fork:
```bash
git clone https://github.com/your-username/wazuh-dfn.git
cd wazuh-dfn
```

2. Set up development environment:
```bash
python3.12 -m virtualenv venv
source venv/bin/activate
pip install -e ".[dev]"
```

3. Install pre-commit hooks:
```bash
pre-commit install
```

## Running Tests

- Run all tests:
```bash
pytest
```

- Run specific test:
```bash
pytest tests/test_specific.py
```

- Run with coverage:
```bash
pytest --cov=wazuh_dfn --cov-report=html
```

## Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add comments for complex logic
- Update configuration examples if needed

## Questions or Problems?

- Open an issue for bugs
- Use discussions for questions
- Tag maintainers for urgent issues

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).
