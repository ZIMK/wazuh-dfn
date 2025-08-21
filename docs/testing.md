# Testing Guide

This document explains how to run different types of tests in the Wazuh DFN project.

## Test Categories

### Unit Tests
Fast tests that test individual components in isolation without external dependencies.

### Integration Tests
Slower tests that test components working together, including:
- Real HTTP server setup
- Network communication
- Authentication and security features
- Rate limiting behavior

## Running Tests

### Run All Unit Tests (Default)
```bash
# Default behavior - runs only unit tests, skips integration tests
pytest

# Explicitly run unit tests only
pytest -m "not integration"
```

### Run Integration Tests Only
```bash
# Run all integration tests (takes longer ~12-15 seconds)
pytest -m integration

# Run specific integration test files
pytest tests/integration/test_api_background.py -m integration
pytest tests/integration/test_api_security.py -m integration
```

### Run All Tests
```bash
# Run both unit and integration tests
pytest -m "integration or not integration"

# Or simply disable the default marker filtering
pytest --ignore-markers
```

### Run Specific Test Categories
```bash
# Run performance tests
pytest -m performance

# Run everything except performance and integration
pytest -m "not performance and not integration"
```

## Test Markers

The project uses pytest markers to categorize tests:

- `@pytest.mark.integration`: Marks tests that require server setup and longer execution time
- `@pytest.mark.performance`: Marks performance/benchmark tests

## Configuration

Test behavior is configured in `pyproject.toml`:
- Default markers: `-m 'not performance and not integration'`
- Integration tests are excluded by default for faster development workflow
- Run integration tests explicitly when needed (e.g., before commits, in CI/CD)

## Best Practices

1. **Development**: Run unit tests frequently (`pytest`) for fast feedback
2. **Pre-commit**: Run integration tests (`pytest -m integration`) to verify complete functionality
3. **CI/CD**: Run all tests to ensure full coverage
4. **Debugging**: Run specific test files or functions for focused testing

## Examples

```bash
# Quick development cycle
pytest

# Before committing changes
pytest -m integration

# Full test suite (for CI/CD)
pytest -m "integration or not integration"

# Test specific functionality
pytest tests/health/api/ -v
pytest tests/integration/test_api_security.py::test_rate_limiting -v
```
