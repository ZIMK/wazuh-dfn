Wazuh-DFN Usage Guide
===================

This document provides instructions for running and using the wazuh-dfn integration in various environments.

Basic Usage
---------

After installation, you can run wazuh-dfn with the following command:

.. code-block:: bash

   wazuh-dfn --config /path/to/config.yaml

or with a TOML configuration file:

.. code-block:: bash

   wazuh-dfn --config /path/to/config.toml --config-format toml

Command-Line Arguments
-------------------

Here are the available command-line arguments:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Argument
     - Description
   * - --config
     - Path to configuration file
   * - --config-format
     - Configuration file format (yaml or toml)
   * - --version
     - Show version information and exit
   * - --print-config-only
     - Prints only config to console
   * - --skip-path-validation
     - Skip validation of paths in config files
   * - --generate-sample-config
     - Generate a sample configuration file
   * - --output-format
     - Format for sample configuration (yaml or toml)
   * - --help-all
     - Show all configuration fields with their CLI arguments and environment variables

You can also use a wide range of direct configuration parameters. To see all options:

.. code-block:: bash

   wazuh-dfn --help-all

For a complete list of configuration options, see the `Configuration Guide <configuration.html>`_.

Asyncio Service Operation
-----------------------

The wazuh-dfn service uses asyncio for all operations, which provides several benefits:

1. **Concurrent Processing**: Multiple alerts are processed simultaneously
2. **Non-blocking I/O**: File, network, and Kafka operations don't block the main thread
3. **Efficient Resource Usage**: Better CPU and memory utilization
4. **Graceful Shutdown**: Clean handling of termination signals

The service structure consists of several concurrent tasks:

- File monitoring task (AlertsWatcherService)
- Worker tasks (AlertsWorkerService) - multiple configurable workers
- Kafka client task (KafkaService)
- Health monitoring task (HealthService) - collects runtime metrics and provides an optional HTTP API

You can configure the number of worker tasks with the `--misc-num-workers` parameter or `misc.num_workers` in the configuration file.

Running as a Service
-----------------

Systemd Service (Linux)
~~~~~~~~~~~~~~~~~~~~~

To run wazuh-dfn as a systemd service, create a service file in ``/etc/systemd/system/wazuh-dfn.service``:

.. code-block:: ini

   [Unit]
   Description=Wazuh DFN Integration Service
   After=network.target wazuh-manager.service
   Requires=wazuh-manager.service

   [Service]
   Type=simple
   User=wazuh
   Group=wazuh
   ExecStart=/usr/local/bin/wazuh-dfn --config /etc/wazuh-dfn/config.toml --config-format toml
   Restart=on-failure
   RestartSec=10
   StandardOutput=journal
   StandardError=journal
   SyslogIdentifier=wazuh-dfn

   [Install]
   WantedBy=multi-user.target

Then enable and start the service:

.. code-block:: bash

   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-dfn
   sudo systemctl start wazuh-dfn

To check the service status:

.. code-block:: bash

   sudo systemctl status wazuh-dfn

To view logs:

.. code-block:: bash

   sudo journalctl -u wazuh-dfn -f

Windows Service
~~~~~~~~~~~~

To install and run as a Windows service, you can use ``nssm`` (Non-Sucking Service Manager):

1. Download and install `NSSM <https://nssm.cc/>`_
2. Open a Command Prompt as Administrator and run:

.. code-block:: doscon

   nssm install WazuhDFN

3. In the NSSM dialog:
   - Set the Path to your Python executable
   - Set the Startup Directory to your wazuh-dfn directory
   - Set Arguments to ``-m wazuh_dfn --config C:\path\to\config.toml --config-format toml``
   - Set Service Name to "WazuhDFN"
   - Configure other options as needed

4. Start the service:

.. code-block:: doscon

   nssm start WazuhDFN

Docker
~~~~~

To run wazuh-dfn in Docker:

1. Create a ``Dockerfile``:

.. code-block:: dockerfile

   FROM python:3.12-slim

   WORKDIR /app

   RUN pip install --no-cache-dir wazuh-dfn

   COPY config.toml /etc/wazuh-dfn/config.toml

   # Create directories
   RUN mkdir -p /opt/wazuh-dfn/certs /opt/wazuh-dfn/failed-alerts /var/log/wazuh-dfn

   # Volume for certificates, logs, and configuration
   VOLUME ["/opt/wazuh-dfn/certs", "/var/log/wazuh-dfn", "/etc/wazuh-dfn"]

   CMD ["wazuh-dfn", "--config", "/etc/wazuh-dfn/config.toml", "--config-format", "toml"]

2. Build the Docker image:

.. code-block:: bash

   docker build -t wazuh-dfn .

3. Run the container:

.. code-block:: bash

   docker run -d \
     --name wazuh-dfn \
     -v $(pwd)/certs:/opt/wazuh-dfn/certs \
     -v $(pwd)/logs:/var/log/wazuh-dfn \
     -v $(pwd)/config.toml:/etc/wazuh-dfn/config.toml \
     --network host \
     wazuh-dfn

Note: Using ``--network host`` is generally required for accessing Unix domain sockets from within a container.

Environment Variables
------------------

You can also configure wazuh-dfn using environment variables. This is particularly useful in containerized environments:

.. code-block:: bash

   export DFN_BROKER_ADDRESS="kafka.dfn-cert.de:443"
   export DFN_CUSTOMER_ID="your-customer-id"
   export WAZUH_UNIX_SOCKET_PATH="/var/ossec/queue/sockets/queue"
   export WAZUH_JSON_ALERT_FILE="/var/ossec/logs/alerts/alerts.json"
   export LOG_LEVEL="INFO"
   export MISC_NUM_WORKERS="10"

   wazuh-dfn

Monitoring and Performance Tuning
------------------------------

Logs and Statistics
~~~~~~~~~~~~~~~~~

The service logs various metrics and information at regular intervals:

- Alert processing statistics (alerts/second, error rates)
- Memory and CPU usage
- Queue size information
- Kafka connection status
- File monitoring status

If you've enabled file logging, logs will be written to the configured file path with automatic rotation.

Performance Tuning
~~~~~~~~~~~~~~~~

You can tune the service performance by adjusting these parameters:

1. **Worker Count**: Increase for more parallel processing
   
   .. code-block:: bash
      
      # In config file (TOML)
      [misc]
      num_workers = 20
      
      # Or via command line
      wazuh-dfn --misc-num-workers 20
      
2. **Queue Size**: Adjust based on memory availability and throughput needs
   
   .. code-block:: bash
      
      # In config file (TOML)
      [wazuh]
      json_alert_queue_size = 200000
      
3. **File Monitoring Interval**: Adjust how frequently to check for new alerts
   
   .. code-block:: bash
      
      # In config file (TOML)
      [wazuh]
      json_alert_file_poll_interval = 0.5  # Check every 0.5 seconds

4. **Logging Interval**: Change how frequently statistics are logged
   
   .. code-block:: bash
      
      # In config file (TOML)
      [log]
      interval = 300  # Log stats every 5 minutes

Health Checks
~~~~~~~~~~~

To check if the service is running correctly:

1. Verify logs show successful connections to both Wazuh and Kafka
2. Check that alerts are being processed without errors
3. Monitor the statistics for processing rate and queue size
4. Verify no excessive CPU or memory usage

Health API (optional)
~~~~~~~~~~~~~~~~~~~~~

The HealthService exposes an optional HTTP API for runtime health and metrics. The API is disabled by default and binds to `127.0.0.1` for safety.

Enable the API via configuration or environment variables:

.. code-block:: bash

   export HEALTH_HTTP_SERVER_ENABLED=true
   export HEALTH_API_HOST=127.0.0.1
   export HEALTH_API_PORT=8080

To query the API (example):

.. code-block:: bash

   curl -H "Authorization: Bearer your_secure_token" http://127.0.0.1:8080/health

Available endpoints include `/health`, `/health/detailed`, `/health/system`, `/health/services`, `/health/workers`, and `/server-info`.

Troubleshooting
------------

Common Issues
~~~~~~~~~~~

1. **Connection to Wazuh socket fails**:
   - Verify the Wazuh manager is running
   - Check socket path permissions
   - Ensure the service has access to the socket

2. **Connection to Kafka fails**:
   - Verify certificates are correctly configured
   - Check network connectivity to Kafka broker
   - Ensure the topic exists
   - Examine retry logs for specific error patterns

3. **Alert file not being monitored**:
   - Verify the alert file path exists
   - Check file permissions
   - Ensure Wazuh is generating alerts
   - Check for file rotation issues

4. **High memory usage**:
   - Reduce queue size
   - Increase number of workers to process alerts faster
   - Check for memory leaks in alert handlers

5. **Failed alert processing**:
   - Enable `store_failed_alerts` option to capture problematic alerts
   - Examine the failed alerts for format issues

Diagnostic Commands
~~~~~~~~~~~~~~~~

To check current configuration:

.. code-block:: bash

   wazuh-dfn --print-config-only --config /path/to/config.toml

To check Wazuh socket:

.. code-block:: bash

   ls -la /var/ossec/queue/sockets/queue

To manually test Kafka connectivity (using kcat):

.. code-block:: bash

   kcat -b kafka.dfn-cert.de:443 -X security.protocol=ssl \
        -X ssl.ca.location=/opt/wazuh-dfn/certs/dfn-ca.pem \
        -X ssl.certificate.location=/opt/wazuh-dfn/certs/dfn-cert.pem \
        -X ssl.key.location=/opt/wazuh-dfn/certs/dfn-key.pem \
        -L

Security Considerations
--------------------

1. **Certificate Security**:
   - Keep private keys secure and restrict access
   - Use proper file permissions (0600) for key files
   - Rotate certificates according to your security policy

2. **Network Access**:
   - Restrict network access to only required services
   - Use firewalls to control traffic between systems

3. **File Permissions**:
   - Ensure log files have appropriate permissions
   - Run the service with least privilege

4. **Service Account**:
   - Create a dedicated user for running the service
   - Restrict the user's permissions to only what's needed

5. **Failed Alert Storage**:
   - If storing failed alerts, ensure the storage location is secure
   - Regularly clean up old failed alerts to prevent disk space issues