Health Monitoring
=================

Overview
--------

The HealthService replaces the legacy LoggingService for periodic runtime statistics. It provides:

- Periodic, bounded health statistics collection (CPU, memory, worker performance, queue stats)
- A small optional HTTP REST API to query current health and metrics
- Configurable thresholds, retention, and rate limiting
- Secure access via bearer token and IP allowlists

Configuration
-------------

The health system is configured via the `health` section in the main configuration file or via environment variables.

Key configuration options:

- `health.stats_interval` (int): Health statistics collection interval in seconds. Environment variable: `HEALTH_STATS_INTERVAL`. Default: 600
- `health.history_retention` (int): Period (in seconds) to keep history entries. Environment variable: `HEALTH_HISTORY_RETENTION`. Default: 3600
- `health.max_history_entries` (int): Maximum number of history entries to prevent unbounded growth. Environment variable: `HEALTH_MAX_HISTORY_ENTRIES`. Default: 1000
- `health.event_queue_size` (int): Maximum queued health events. Environment variable: `HEALTH_EVENT_QUEUE_SIZE`. Default: 50

API server configuration (optional):

- `health.api.enabled` (bool): Master flag to enable HTTP server. Environment variable: `HEALTH_HTTP_SERVER_ENABLED`. Default: false
- `health.api.host` (str): Host to bind to (default `127.0.0.1`) — recommended for security
- `health.api.port` (int): Port to bind to (default 8080)
- `health.api.auth_token` (str): Optional bearer token for API access. Environment variable: `HEALTH_API_AUTH_TOKEN`
- `health.api.allowed_ips` (list): Optional IP allowlist (CIDR supported). Environment variable: `HEALTH_API_ALLOWED_IPS`
- `health.api.rate_limit` (int): Requests per minute rate limit. Environment variable: `HEALTH_API_RATE_LIMIT`

Usage
-----

The HealthService runs as part of the main daemon and collects metrics in the background. The HTTP server is optional and remains disabled by default for safety. To enable the server set `health.api.enabled` to `true` in the config or set `HEALTH_HTTP_SERVER_ENABLED=true`.

Example (bash):

.. code-block:: bash

   export HEALTH_HTTP_SERVER_ENABLED=true
   export HEALTH_API_HOST=127.0.0.1
   export HEALTH_API_PORT=8080
   export HEALTH_API_AUTH_TOKEN="your_secure_token"
   python -m wazuh_dfn

Example (PowerShell):

.. code-block:: powershell

   $env:HEALTH_HTTP_SERVER_ENABLED = 'true'
   $env:HEALTH_API_HOST = '127.0.0.1'
   $env:HEALTH_API_PORT = '8080'
   $env:HEALTH_API_AUTH_TOKEN = 'your_secure_token'
   python -m wazuh_dfn

Endpoints
---------

The HTTP API exposes the following endpoints when enabled:

- GET /health - Overall health status
- GET /health/detailed - Detailed health metrics
- GET /health/system - System resource information
- GET /health/services - Individual service status
- GET /health/workers - Worker performance metrics
- GET /server-info - API server information

Migration from LoggingService
-----------------------------

If you previously used the LoggingService to emit periodic statistics via `log.interval` or the `LOG_INTERVAL` environment variable, follow these steps to migrate:

1. Move the interval value to `health.stats_interval` or set `HEALTH_STATS_INTERVAL` in the environment.
2. Enable the API server (optional) via `health.api.enabled: true` or `HEALTH_HTTP_SERVER_ENABLED=true` if you need remote access to metrics.
3. Secure the API using `health.api.auth_token` and `health.api.allowed_ips`.
4. Remove or keep `log.interval` — it will still configure the legacy LoggingService interval, but the application will emit a migration warning when it is used.

Security and best practices
---------------------------

- Keep `health.api.host` set to `127.0.0.1` unless you intentionally expose it.
- Use a bearer token and IP allowlist for production deployments.
- Monitor `health.max_history_entries` and `health.event_queue_size` to control memory usage.

