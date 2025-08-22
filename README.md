# wazuh-dfn <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release-pre/ZIMK/wazuh-dfn.svg)](https://github.com/ZIMK/wazuh-dfn/releases)

The `wazuh-dfn` is a specialized daemon that integrates Wazuh with DFN-CERT services. It monitors Wazuh alert files and forwards relevant security events to the DFN SOC (Security Operations Center) for advanced analysis and threat detection. The service is built with asyncio for efficient, non-blocking I/O operations, resulting in high performance and scalability.

## Table of Contents <!-- omit in toc -->

- [Documentation](#documentation)
- [Features](#features)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Install using pip](#install-using-pip)
  - [Install from source](#install-from-source)
- [Configuration](#configuration)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Documentation

The documentation for wazuh-dfn can be found at
[https://zimk.github.io/wazuh-dfn/](https://zimk.github.io/wazuh-dfn/).
Please always take a look at the documentation for further details. This
**README** just gives you a short overview.

## Features

- **Asynchronous Architecture**: Built with Python's asyncio for non-blocking I/O operations
- **High Performance**: Efficiently processes large volumes of alerts with minimal overhead
- **Robust Error Handling**: Features automatic reconnection, queue management, and error recovery
- **Secure Communication**: TLS/SSL support for Kafka communication with certificate validation
- **Specialized Alert Handlers**: Modular design with dedicated handlers for different alert types
- **Flexible Configuration**: Supports YAML, TOML, environment variables, and CLI arguments
- **Comprehensive Monitoring**: Detailed logging and performance metrics
- **Resource Management**: Dynamic queue management to control memory usage
- **File Monitoring**: Reliable alert file monitoring with rotation detection and partial alert handling
- **Advanced Health Monitoring**: Real-time health monitoring with REST API endpoints
  - **REST API Server**: Optional HTTP server for health status queries (`pip install wazuh-dfn[health-api]`)
  - **Security Features**: Bearer token authentication, IP allowlists (CIDR), rate limiting, HTTPS support
  - **Real-time Metrics**: System resources, service health, worker performance, and Kafka statistics
  - **Dependency Injection**: ServiceContainer architecture eliminates circular dependencies
  - **Event-driven Architecture**: Push/pull hybrid system for comprehensive health data collection

## Installation

### Requirements

Python 3.12 or later is required. The project uses modern Python features including asyncio for asynchronous operations.

### Install using pip

You can install the latest stable release of wazuh-dfn from the Python Package
Index using [pip](https://pip.pypa.io/):

```bash
python3 -m pip install wazuh-dfn
```

### Install from source

To install from source:

```bash
git clone https://github.com/ZIMK/wazuh-dfn.git
cd wazuh-dfn
python -m pip install --upgrade pip pdm
pdm install
```

## Configuration

The `wazuh-dfn` service can be configured through various methods, in order of precedence:

1. Command-line arguments
2. Environment variables
3. Configuration file (YAML or TOML)

Generate a sample configuration:

```bash
wazuh-dfn --generate-sample-config --output-format toml
```

For all available options:

```bash
wazuh-dfn --help-all
```

### Health Monitoring Configuration

The health monitoring system provides real-time insights into service performance and system status. To enable the optional REST API server:

1. **Install health API dependencies**:
   ```bash
   pip install wazuh-dfn[health-api]
   ```

2. **Enable the HTTP server**:
   ```bash
   export HEALTH_HTTP_SERVER_ENABLED=true
   export HEALTH_API_HOST=127.0.0.1  # Default: localhost only
   export HEALTH_API_PORT=8080       # Default port
   ```

3. **Optional security configuration**:
   ```bash
   # Authentication
   export HEALTH_API_AUTH_TOKEN=your_secure_token
   
   # IP allowlist (CIDR notation supported)
   export HEALTH_API_ALLOWED_IPS=127.0.0.1,192.168.1.0/24,::1
   
   # Rate limiting (requests per minute)
   export HEALTH_API_RATE_LIMIT=100
   
   # HTTPS support
   export HEALTH_API_HTTPS_ENABLED=true
   export HEALTH_API_CERT_FILE=/path/to/cert.pem
   export HEALTH_API_KEY_FILE=/path/to/key.pem
   ```

4. **Health monitoring endpoints**:
   - `GET /health` - Overall health status
   - `GET /health/detailed` - Detailed health metrics
   - `GET /health/system` - System resource information
   - `GET /health/services` - Individual service status
   - `GET /health/workers` - Worker performance metrics
   - `GET /server-info` - API server information

The health monitoring system runs independently of the REST API and provides continuous monitoring even when the HTTP server is disabled.

### Migration: LoggingService -> HealthService

The project replaces the legacy periodic LoggingService (which emitted statistics at `LogConfig.interval` / `LOG_INTERVAL`) with the new HealthService and `HealthConfig` (`HEALTH_STATS_INTERVAL`).

- The `LogConfig` still configures normal logging outputs (console/file/level). Only the periodic LoggingService is deprecated.
- If you previously relied on `LOG_INTERVAL` or `log.interval` to emit periodic statistics, migrate that value to `HEALTH_STATS_INTERVAL` or `health.stats_interval`.
- If `LOG_INTERVAL` is present at runtime, the application will log a migration warning to assist moving to the new health configuration.

Quick examples — enable the health API server (disabled by default):

Bash example:
```bash
# Enable health API server (defaults to disabled)
export HEALTH_HTTP_SERVER_ENABLED=true
export HEALTH_API_HOST=127.0.0.1
export HEALTH_API_PORT=8080

# Optional: secure the API with a bearer token
export HEALTH_API_AUTH_TOKEN=your_secure_token

# Start the service (example entrypoint)
python -m wazuh_dfn
```

PowerShell example:
```powershell
# Enable health API server
$env:HEALTH_HTTP_SERVER_ENABLED = 'true'
$env:HEALTH_API_HOST = '127.0.0.1'
$env:HEALTH_API_PORT = '8080'

# Optional: secure the API with a bearer token
$env:HEALTH_API_AUTH_TOKEN = 'your_secure_token'

# Start the service (example entrypoint)
python -m wazuh_dfn
```

Security note: the API is intentionally disabled by default and binds to `127.0.0.1` unless you explicitly change `HEALTH_API_HOST`. Use `HEALTH_API_AUTH_TOKEN` and IP allowlists to restrict access.

### Troubleshooting Health Monitoring

**HTTP Server Issues:**
- If `HEALTH_HTTP_SERVER_ENABLED=true` but the server doesn't start, check that `aiohttp` is installed: `pip install wazuh-dfn[health-api]`
- The server defaults to `127.0.0.1` (localhost only) for security. Set `HEALTH_API_HOST=0.0.0.0` to accept external connections
- Check logs for specific error messages related to port binding or certificate issues

**Authentication Issues:**
- Bearer token authentication requires the `Authorization: Bearer <token>` header
- Ensure the token matches the `HEALTH_API_AUTH_TOKEN` environment variable exactly
- IP allowlist uses CIDR notation - ensure your client IP is included in `HEALTH_API_ALLOWED_IPS`

**Performance Monitoring:**
- Health monitoring continues even if the HTTP server fails
- Check logs for health service status and performance metrics
- Memory usage is bounded by configurable thresholds to prevent resource exhaustion

## Support
If you found a problem with the software, please
[create an issue](https://github.com/ZIMK/wazuh-dfn/issues)
on GitHub.

## Maintainer

This project is maintained by [University of Trier - ZIMK](http://zimk.uni-trier.de/).

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/ZIMK/wazuh-dfn/pulls) on GitHub.
For bigger changes, please discuss it first in the
[issues](https://github.com/ZIMK/wazuh-dfn/issues).

For development setup instructions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the LICENSE file for details.
