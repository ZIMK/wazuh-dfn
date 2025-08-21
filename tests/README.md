# Test organization for wazuh-dfn

This document describes the test organization for the wazuh-dfn project. It explains where tests live, following a structured approach that mirrors the source code structure.

## Directory layout

The tests directory structure mirrors the source code structure:

```
./
├── tests/
│   ├── conftest.py                         — shared pytest fixtures and helpers
│   ├── test_config.py                      — configuration parsing and validation utilities
    │   ├── test_exceptions.py                  — project-specific exception classes
    │   ├── test_main.py                        — application entry point and CLI wiring
    │   ├── test_service_container.py           — dependency/service container and wiring helpers
    │   ├── test___main__.py                    — CLI entrypoint behaviour (python -m wazuh_dfn)
    │   ├── health/
    │   │   ├── test_builders.py                — helpers to construct health-related objects and dependencies
    │   │   ├── test_event_service.py           — event generation and dispatch for health monitoring
    │   │   ├── test_health_service.py          — core health-check logic and orchestration
    │   │   ├── test_models.py                  — data models for health API payloads
    │   │   ├── test_protocols.py               — protocol/interface definitions used by health services
    │   │   └── api/
    │   │       ├── test_handlers.py           — HTTP request handlers for the health API
    │   │       ├── test_middleware.py         — request/response middleware components
    │   │       ├── test_rate_limiter.py       — rate limiting utilities for endpoints
    │   │       └── test_server.py             — HTTP server wiring and startup logic
    │   └── services/
    │       ├── test_alerts_service.py         — alert production tests
    │       ├── test_alerts_watcher_service.py — alert watching tests
    │       ├── test_alerts_worker_service.py  — worker processing tests
    │       ├── test_file_monitor.py           — file monitoring behaviour tests
    │       ├── test_kafka_service.py          — Kafka producer/consumer helpers tests
    │       ├── test_logging_service.py        — logging integration and adapter tests
    │       ├── test_max_size_queue.py         — queue behaviour with size limits
    │       ├── test_wazuh_service.py          — Wazuh integration tests
    │       └── handlers/
    │           ├── test_syslog_handler.py     — syslog event handling tests
    │           └── test_windows_handler.py    — Windows event handling tests
```

## Testing Approach and Best Practices

All tests in this project follow these key principles:

1. **Function-based approach**: Tests are written as functions (not classes) following modern pytest conventions
2. **Python 3.12+ compatibility**: Tests utilize modern Python features including:
   - Type hints and annotations
   - F-strings for string formatting
   - Structural pattern matching
   - Self-documenting assertions
   - Modern context managers
3. **Isolation**: Each test function is independent and doesn't rely on state from other tests
4. **Fixtures over setup/teardown**: Using pytest fixtures for test setup and cleanup
5. **Parameterization**: Tests use pytest's parameterize for testing multiple input combinations
6. **Mocking with pytest-mock**: Using the mocker fixture for patching and mocking dependencies

## Running tests

The project uses the pytest configuration in `pyproject.toml`. Run the test suite with your environment's pytest (the repo expects Python >=3.12):

```
pytest
```

The default `pyproject.toml` adds coverage, xml result and html reports; adjust `--maxfail`/`-k` when iterating locally.

## Quick notes

- Mark performance tests with `@pytest.mark.performance(threshold, "description")` as configured in `pyproject.toml`.
- Keep `tests/conftest.py` minimal and explicit about fixtures it provides.
- When adding integration tests that require services (GVM, email), document required external resources and prefer dockerized fixtures where possible.
