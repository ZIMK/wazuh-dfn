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
