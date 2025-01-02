Configuration Methods
=====================

The service can be configured in three ways, with the following
precedence (highest to lowest):

1. Command-line arguments
2. Environment variables
3. Configuration file (YAML)

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

Here’s a comprehensive list of all configuration options and how to set
them:

DFN Configuration
^^^^^^^^^^^^^^^^^

.. list-table:: DFN Configuration
   :header-rows: 1

   * - Option
     - YAML Key
     - Environment Variable
     - CLI Argument
     - Default
     - Description
   * - Customer ID
     - `dfn.dfn_id`
     - `DFN_CUSTOMER_ID`
     - `--dfn-customer-id`
     - None
     - DFN customer ID
   * - Broker Address
     - `dfn.dfn_broker`
     - `DFN_BROKER_ADDRESS`
     - `--dfn-broker-address`
     - kafka.example.org:443
     - DFN Kafka broker address
   * - CA Certificate
     - `dfn.dfn_ca`
     - `DFN_CA_PATH`
     - `--dfn-ca-path`
     - /opt/wazuh-dfn/certs/dfn-ca.pem
     - Path to CA certificate for Kafka SSL
   * - Client Certificate
     - `dfn.dfn_cert`
     - `DFN_CERT_PATH`
     - `--dfn-cert-path`
     - /opt/wazuh-dfn/certs/dfn-cert.pem
     - Path to client certificate for Kafka SSL
   * - Client Key
     - `dfn.dfn_key`
     - `DFN_KEY_PATH`
     - `--dfn-key-path`
     - /opt/wazuh-dfn/certs/dfn-key.pem
     - Path to client key for Kafka SSL

Wazuh Configuration
^^^^^^^^^^^^^^^^^^^

.. list-table:: Wazuh Configuration
   :header-rows: 1

   * - Option
     - YAML Key
     - Environment Variable
     - CLI Argument
     - Default
     - Description
   * - Socket Path
     - `wazuh.unix_socket_path`
     - `WAZUH_UNIX_SOCKET_PATH`
     - `--wazuh-unix-socket-path`
     - /var/ossec/queue/sockets/queue
     - Path to Wazuh socket
   * - Max Event Size
     - `wazuh.max_event_size`
     - `WAZUH_MAX_EVENT_SIZE`
     - `--wazuh-max-event-size`
     - 65535
     - Maximum size of events to process
   * - Alert File
     - `wazuh.json_alert_file`
     - `WAZUH_JSON_ALERT_FILE`
     - `--wazuh-json-alert-file`
     - /var/ossec/logs/alerts/alerts.json
     - Path to JSON alerts file
   * - Alert Prefix
     - `wazuh.json_alert_prefix`
     - `WAZUH_JSON_ALERT_PREFIX`
     - `--wazuh-json-prefix`
     - {"timestamp"
     - Expected prefix of JSON alert lines
   * - Alert Suffix
     - `wazuh.json_alert_suffix`
     - `WAZUH_JSON_ALERT_SUFFIX`
     - `--wazuh-json-suffix`
     - }
     - Expected suffix of JSON alert lines
   * - Poll Interval
     - `wazuh.json_alert_file_poll_interval`
     - `WAZUH_JSON_ALERT_FILE_POLL_INTERVAL`
     - `--wazuh-json-alert-file-poll-interval`
     - 1.0
     - Interval between file checks (seconds)
   * - Max Retries
     - `wazuh.max_retries`
     - `WAZUH_MAX_RETRIES`
     - `--wazuh-max-retries`
     - 5
     - Maximum number of retries
   * - Retry Interval
     - `wazuh.retry_interval`
     - `WAZUH_RETRY_INTERVAL`
     - `--wazuh-retry-interval`
     - 5
     - Interval between retries (seconds)

Kafka Configuration
^^^^^^^^^^^^^^^^^^^

.. list-table:: Kafka Configuration
   :header-rows: 1

   * - Option
     - YAML Key
     - Environment Variable
     - CLI Argument
     - Default
     - Description
   * - Timeout
     - `kafka.timeout`
     - `KAFKA_TIMEOUT`
     - `--kafka-timeout`
     - 60
     - Kafka request timeout (seconds)
   * - Retry Interval
     - `kafka.retry_interval`
     - `KAFKA_RETRY_INTERVAL`
     - `--kafka-retry-interval`
     - 5
     - Interval between retries (seconds)
   * - Connection Retries
     - `kafka.connection_max_retries`
     - `KAFKA_CONNECTION_MAX_RETRIES`
     - `--kafka-connection-max-retries`
     - 5
     - Maximum connection retry attempts
   * - Send Retries
     - `kafka.send_max_retries`
     - `KAFKA_SEND_MAX_RETRIES`
     - `--kafka-send-max-retries`
     - 5
     - Maximum send retry attempts
   * - Max Wait Time
     - `kafka.max_wait_time`
     - `KAFKA_MAX_WAIT_TIME`
     - `--kafka-max-wait-time`
     - 60
     - Maximum wait time (seconds)
   * - Admin Timeout
     - `kafka.admin_timeout`
     - `KAFKA_ADMIN_TIMEOUT`
     - `--kafka-admin-timeout`
     - 10
     - Admin operation timeout (seconds)
   * - Service Retry Interval
     - `kafka.service_retry_interval`
     - `KAFKA_SERVICE_RETRY_INTERVAL`
     - `--kafka-service-retry-interval`
     - 5
     - Service retry interval (seconds)
   * - Producer Config
     - `kafka.producer_config`
     - `KAFKA_PRODUCER_CONFIG`
     - `--kafka-producer-config`
     - See below
     - Kafka producer configuration

Default producer configuration:

.. code:: yaml

   producer_config:
     request.timeout.ms: 60000
     connections.max.idle.ms: 540000 # 9 minutes
     socket.keepalive.enable: true
     linger.ms: 1000 # Controls how long to wait before sending a batch
     batch.size: 16384 # Maximum size of a batch in bytes
     batch.num.messages: 100 # Maximum number of messages in a batch
     enable.idempotence: true # Ensure exactly-once delivery
     acks: "all" # Wait for all replicas
     statistics.interval.ms: 0 # Disable stats for better performance
     log_level: 0 # Only log errors

Logging Configuration
^^^^^^^^^^^^^^^^^^^^^

.. list-table:: Logging Configuration
   :header-rows: 1

   * - Option
     - YAML Key
     - Environment Variable
     - CLI Argument
     - Default
     - Description
   * - Console Logging
     - `log.console`
     - `LOG_CONSOLE_ENABLED`
     - `--log-console-enabled`
     - true
     - Enable console logging
   * - Log File
     - `log.file_path`
     - `LOG_FILE_PATH`
     - `--log-file-path`
     - /opt/wazuh-dfn/logs/wazuh-dfn.log
     - Path to log file
   * - Log Interval
     - `log.interval`
     - `LOG_INTERVAL`
     - `--log-interval`
     - 600
     - Statistics logging interval (seconds)
   * - Log Level
     - `log.level`
     - `LOG_LEVEL`
     - `--log-level`
     - INFO
     - Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

Miscellaneous Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table:: Miscellaneous Configuration
   :header-rows: 1

   * - Option
     - YAML Key
     - Environment Variable
     - CLI Argument
     - Default
     - Description
   * - Worker Threads
     - `misc.num_workers`
     - `MISC_NUM_WORKERS`
     - `--misc-num-workers`
     - 10
     - Number of worker threads
   * - Own Network
     - `misc.own_network`
     - `MISC_OWN_NETWORK`
     - `--misc-own-network`
     - None
     - Own network CIDR notation (optional)

Configuration Examples
~~~~~~~~~~~~~~~~~~~~~~

Using Environment Variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   # Required DFN settings
   export DFN_CUSTOMER_ID="12345678-abcd-efgh-ijkl-01234567890ab"
   export DFN_BROKER_ADDRESS="kafka.example.org:443"
   export DFN_CA_PATH="/opt/wazuh-dfn/certs/dfn-ca.pem"
   export DFN_CERT_PATH="/opt/wazuh-dfn/certs/dfn-cert.pem"
   export DFN_KEY_PATH="/opt/wazuh-dfn/certs/dfn-key.pem"

   # Logging configuration
   export LOG_CONSOLE_ENABLED="true"
   export LOG_FILE_PATH="/opt/wazuh-dfn/logs/wazuh-dfn.log"
   export LOG_INTERVAL="600"
   export LOG_LEVEL="INFO"

   # Miscellaneous settings
   export MISC_NUM_WORKERS="10"
   # Optional: Network CIDR for own network filtering
   # export MISC_OWN_NETWORK="192.0.2.0/24"

   # Start the service
   wazuh-dfn -c /opt/wazuh-dfn/config/config.yaml

Using Command Line Arguments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   wazuh-dfn -c /opt/wazuh-dfn/config/config.yaml \
     --dfn-customer-id "12345678-abcd-efgh-ijkl-01234567890ab" \
     --dfn-broker-address "kafka.example.org:443" \
     --dfn-ca-path "/opt/wazuh-dfn/certs/dfn-ca.pem" \
     --dfn-cert-path "/opt/wazuh-dfn/certs/dfn-cert.pem" \
     --dfn-key-path "/opt/wazuh-dfn/certs/dfn-key.pem" \
     --log-console-enabled true \
     --log-file-path "/opt/wazuh-dfn/logs/wazuh-dfn.log" \
     --log-interval 600 \
     --log-level INFO \
     --misc-num-workers 10

Using YAML Configuration
^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: yaml

   # Wazuh DFN Service Configuration

   # Required DFN settings - these must be configured
   dfn:
     dfn_id: "12345678-abcd-efgh-ijkl-01234567890ab" # DFN customer ID
     dfn_broker: "kafka.example.org:443" # DFN Kafka broker address
     dfn_ca: "/opt/wazuh-dfn/certs/dfn-ca.pem" # Path to CA certificate for Kafka SSL
     dfn_cert: "/opt/wazuh-dfn/certs/dfn-cert.pem" # Path to client certificate for Kafka SSL
     dfn_key: "/opt/wazuh-dfn/certs/dfn-key.pem" # Path to client key for Kafka SSL

   # Logging configuration
   log:
     console: true # Enable console logging
     file_path: "/opt/wazuh-dfn/logs/wazuh-dfn.log" # Path to log file
     interval: 600 # Statistics logging interval in seconds
     level: "INFO" # Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL

   # Miscellaneous settings
   misc:
     num_workers: 10 # Number of worker threads for processing alerts
     own_network: # Optional: Network CIDR for own network filtering (e.g. "192.0.2.0/24")
