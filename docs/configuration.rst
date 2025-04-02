Configuration
=============

This section covers the configuration options for the wazuh-dfn service. The service supports multiple configuration methods with the following precedence (highest to lowest):

1. Command-line arguments
2. Environment variables
3. Configuration file (YAML or TOML)

Configuration File Formats
--------------------------

The service supports both YAML and TOML configuration formats. You can generate a sample configuration file using:

.. code-block:: bash

    # Generate TOML configuration (recommended)
    wazuh-dfn --generate-sample-config --output-format toml
    
    # Or generate YAML configuration
    wazuh-dfn --generate-sample-config --output-format yaml

Configuration Sections
----------------------

The configuration is organized into several sections:

DFN Configuration
^^^^^^^^^^^^^^^^^^

Settings related to DFN-CERT services and authentication:

.. code-block:: toml

    [dfn]
    # DFN Kafka broker address
    dfn_broker = "kafka.example.org:443"
    
    # Path to CA certificate for Kafka SSL
    dfn_ca = "/opt/wazuh-dfn/certs/dfn-ca.pem"
    
    # Path to client certificate for Kafka SSL
    dfn_cert = "/opt/wazuh-dfn/certs/dfn-cert.pem"
    
    # Path to client key for Kafka SSL
    dfn_key = "/opt/wazuh-dfn/certs/dfn-key.pem"
    
    # DFN customer ID (required)
    dfn_id = "your-customer-id"

Wazuh Configuration
^^^^^^^^^^^^^^^^^^^

Settings for connecting to Wazuh and processing alerts:

.. code-block:: toml

    [wazuh]
    # Path to Wazuh socket (Unix socket path or tuple of host and port for TCP)
    unix_socket_path = "/var/ossec/queue/sockets/queue"
    
    # Maximum size of events to process
    max_event_size = 65535
    
    # Full path to the JSON alerts file to monitor
    json_alert_file = "/var/ossec/logs/alerts/alerts.json"
    
    # Expected prefix of JSON alert lines
    json_alert_prefix = '{"timestamp"'
    
    # Expected suffix of JSON alert lines
    json_alert_suffix = "}"
    
    # Maximum number of retries
    max_retries = 42
    
    # Interval between retries in seconds
    retry_interval = 5
    
    # Interval in seconds between JSON alert file checks
    json_alert_file_poll_interval = 1.0
    
    # Whether to store failed alerts for later analysis
    store_failed_alerts = false
    
    # Directory path to store failed alerts
    failed_alerts_path = "/opt/wazuh-dfn/failed-alerts"
    
    # Maximum number of failed alert files to keep
    max_failed_files = 100
    
    # Maximum number of alerts to queue for processing
    json_alert_queue_size = 100000

Kafka Configuration
^^^^^^^^^^^^^^^^^^^

Advanced Kafka client settings:

.. code-block:: toml

    [kafka]
    # Kafka request timeout in seconds
    timeout = 60
    
    # Interval between retries in seconds
    retry_interval = 5
    
    # Maximum number of connection retries
    connection_max_retries = 5
    
    # Maximum number of send retries
    send_max_retries = 5
    
    # Maximum wait time between retries in seconds
    max_wait_time = 60
    
    # Timeout for admin operations in seconds
    admin_timeout = 10
    
    # Interval between service retries in seconds
    service_retry_interval = 5

Logging Configuration
^^^^^^^^^^^^^^^^^^^^^

Settings for logging and statistics:

.. code-block:: toml

    [log]
    # Enable console logging
    console = true
    
    # Number of log files to keep when rotating
    keep_files = 5
    
    # Statistics logging interval in seconds
    interval = 600
    
    # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    level = "INFO"
    
    # Path to log file
    file_path = "/var/log/wazuh-dfn.log"

Miscellaneous Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Other service settings:

.. code-block:: toml

    [misc]
    # Number of worker tasks (for asyncio worker pool)
    num_workers = 10
    
    # Own network CIDR notation (optional)
    # Use this to identify "internal" IPs that should be ignored
    own_network = "192.168.0.0/16"

Environment Variables
---------------------

All configuration options can also be set using environment variables. The naming convention is:

- DFN settings: `DFN_*` (e.g., `DFN_BROKER_ADDRESS`)
- Wazuh settings: `WAZUH_*` (e.g., `WAZUH_JSON_ALERT_FILE`)
- Kafka settings: `KAFKA_*` (e.g., `KAFKA_TIMEOUT`)
- Log settings: `LOG_*` (e.g., `LOG_LEVEL`)
- Misc settings: `MISC_*` (e.g., `MISC_NUM_WORKERS`)

For a complete list of environment variables, run:

.. code-block:: bash

    wazuh-dfn --help-all

Command-Line Arguments
----------------------

Command-line arguments have the highest precedence and override both configuration file settings and environment variables:

.. code-block:: bash

    wazuh-dfn --dfn-broker-address "kafka.example.org:443" --log-level "DEBUG"

To see all available command-line options:

.. code-block:: bash

    wazuh-dfn --help

For a complete list of all configuration options with descriptions:

.. code-block:: bash

    wazuh-dfn --help-all

Verifying Configuration
-----------------------

To verify your configuration without starting the service:

.. code-block:: bash

    wazuh-dfn --print-config-only --config /path/to/config.toml

Best Practices
--------------

1. **Start with a sample configuration**:
   Generate a sample config and customize it for your environment:
   
   .. code-block:: bash
       
       wazuh-dfn --generate-sample-config --output-format toml > config.toml
       
2. **Use secure defaults**:
   - Enable TLS/SSL with proper certificate validation
   - Set appropriate retry limits and timeouts
   - Configure proper logging for troubleshooting
   
3. **Tune worker count**:
   Adjust `num_workers` based on your CPU resources and alert volume
   
4. **Monitor performance**:
   Use the logging service's statistics to monitor alert processing performance

Next Steps
----------

After configuring the service, proceed to the :doc:`usage` section to learn how to run and manage the service.
