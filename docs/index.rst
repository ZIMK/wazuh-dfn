Wazuh-DFN Documentation
=======================

Welcome to the Wazuh-DFN documentation!

Wazuh-DFN is a specialized daemon that integrates Wazuh with DFN-CERT services. It monitors Wazuh alert files and forwards relevant security events to the DFN SOC (Security Operations Center) for advanced analysis and threat detection. The service is built with asyncio for efficient, non-blocking I/O operations, resulting in high performance and scalability.

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   about
   installation
   configuration
   usage
   troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: Architecture

   architecture

.. toctree::
   :maxdepth: 2
   :caption: Development

   contributing

Features
--------

- **Asynchronous Architecture**: Built with Python's asyncio for efficient I/O operations
- **Robust Error Handling**: Automatic reconnection, queue management, and error recovery
- **High Performance**: Processes large volumes of alerts with minimal overhead
- **Secure Communication**: TLS/SSL support for Kafka communication
- **Extensible**: Modular design with specialized handlers for different alert types
- **Configurable**: Flexible configuration options via YAML, TOML, environment variables, or CLI arguments
- **Metrics & Logging**: Comprehensive logging and performance metrics

Requirements
------------

- Python 3.12 or later
- Wazuh manager instance
- DFN-CERT Kafka broker access
- TLS/SSL certificates for secure communication

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`