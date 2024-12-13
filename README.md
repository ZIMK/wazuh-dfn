# wazuh-dfn

The `wazuh-dfn` is a specialized daemon that integrates Wazuh with DFN-CERT services. It monitors Wazuh alert files and forwards relevant security events to the DFN SOC (Security Operations Center) for advanced analysis and threat detection.

## Features

- Efficient polling of Wazuh JSON alert file
- Processing of critical Windows security events:
  - Failed login attempts (4625)
  - System audit policy changes (4719)
  - Special privileges assigned to new logon (4672)
  - User account creation (4720)
  - Security log cleared (1102)
  - And more...
- Fail2Ban alert processing
- Secure communication with DFN SOC via Kafka
- Multi-threaded architecture for efficient processing
- Built-in monitoring and statistics

## How It Works

The daemon operates using three main components:

1. **Alert File Watcher**: Efficiently polls the Wazuh JSON alert file for new alerts. It tracks file position and handles file rotation, ensuring no alerts are missed. The watcher:

   - Reads alerts line by line from the JSON alert file
   - Handles file truncation and rotation automatically
   - Uses efficient buffered reading for optimal performance
   - Maintains file position between reads
   - Provides robust error handling for file access issues

2. **Alert Analysis Workers**: Multiple worker threads process queued alerts in parallel. They:

   - Filter relevant security events
   - Transform Windows events to XML schema
   - Add RFC 5424 priority to Fail2Ban messages
   - Forward processed alerts to DFN SOC via Kafka

3. **System Monitor**: Tracks and logs system metrics including:
   - Queue usage and processing rates
   - Memory consumption
   - File processing statistics
   - Kafka producer health
   - Worker thread status

## Prerequisites

- Python 3.12
- Wazuh manager installed
- DFN-CERT membership and valid certificates
- Access to DFN SOC Kafka broker

## Installation

> **Note**: The service will run as the `wazuh` user, so all directories and files must be owned by this user.

### Rocky Linux 9

```bash
# Install system dependencies
sudo dnf update
sudo dnf install python3.12 python3.12-pip

# Create installation directory
sudo mkdir -p /opt/wazuh-dfn
sudo chown wazuh:wazuh /opt/wazuh-dfn

# Create virtual environment
python3.12 -m virtualenv /opt/wazuh-dfn/venv

# Install wazuh-dfn
sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh-dfn
```

### Ubuntu 24.04

```bash
# Install system dependencies
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev gcc

# Create installation directory
sudo mkdir -p /opt/wazuh-dfn
sudo chown wazuh:wazuh /opt/wazuh-dfn

# Create virtual environment
python3.12 -m venv /opt/wazuh-dfn/venv

# Install wazuh-dfn
sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh-dfn
```

## Configuration

1. Create configuration directory and copy the sample configuration:

```bash
mkdir -p /opt/wazuh-dfn/{config,certs,logs}
curl -o /opt/wazuh-dfn/config/config.yaml https://raw.githubusercontent.com/your-repo/wazuh-dfn/main/config.sample.yaml
```

2. Configure the service by editing `/opt/wazuh-dfn/config/config.yaml`. The DFN settings are **required** and must be configured:

```yaml
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
  own_network: # Optional: Network CIDR for own network filtering (e.g. "10.0.0.0/8")
```

3. Important path considerations:

   - If you have a non-default Wazuh installation, you may need to adjust:
     - `wazuh.json_alert_file`: Path to Wazuh's JSON alert file
     - `wazuh.unix_socket_path`: Path to Wazuh's Unix domain socket
   - You can customize the log location by changing:
     - `log.file_path`: Where to store the wazuh-dfn service logs
   - All other settings have sensible defaults and are optional

4. Verify your DFN certificates are in place:

```bash
ls -l /opt/wazuh-dfn/certs/
# Should show:
# dfn-ca.pem
# dfn-cert.pem
# dfn-key.pem
```

## Configuration Methods

The service can be configured in three ways, with the following precedence (highest to lowest):

1. Command-line arguments
2. Environment variables
3. Configuration file (YAML)

### Configuration Options

Here's a comprehensive list of all configuration options and how to set them:

#### DFN Configuration

| Option             | YAML Key         | Environment Variable | CLI Argument           | Default                           | Description                              |
| ------------------ | ---------------- | -------------------- | ---------------------- | --------------------------------- | ---------------------------------------- |
| Customer ID        | `dfn.dfn_id`     | `DFN_CUSTOMER_ID`    | `--dfn-customer-id`    | None                              | DFN customer ID                          |
| Broker Address     | `dfn.dfn_broker` | `DFN_BROKER_ADDRESS` | `--dfn-broker-address` | kafka.example.org:443             | DFN Kafka broker address                 |
| CA Certificate     | `dfn.dfn_ca`     | `DFN_CA_PATH`        | `--dfn-ca-path`        | /opt/wazuh-dfn/certs/dfn-ca.pem   | Path to CA certificate for Kafka SSL     |
| Client Certificate | `dfn.dfn_cert`   | `DFN_CERT_PATH`      | `--dfn-cert-path`      | /opt/wazuh-dfn/certs/dfn-cert.pem | Path to client certificate for Kafka SSL |
| Client Key         | `dfn.dfn_key`    | `DFN_KEY_PATH`       | `--dfn-key-path`       | /opt/wazuh-dfn/certs/dfn-key.pem  | Path to client key for Kafka SSL         |

#### Wazuh Configuration

| Option         | YAML Key                              | Environment Variable                  | CLI Argument                            | Default                            | Description                            |
| -------------- | ------------------------------------- | ------------------------------------- | --------------------------------------- | ---------------------------------- | -------------------------------------- |
| Socket Path    | `wazuh.unix_socket_path`              | `WAZUH_UNIX_SOCKET_PATH`              | `--wazuh-unix-socket-path`              | /var/ossec/queue/sockets/queue     | Path to Wazuh socket                   |
| Max Event Size | `wazuh.max_event_size`                | `WAZUH_MAX_EVENT_SIZE`                | `--wazuh-max-event-size`                | 65535                              | Maximum size of events to process      |
| Alert File     | `wazuh.json_alert_file`               | `WAZUH_JSON_ALERT_FILE`               | `--wazuh-json-alert-file`               | /var/ossec/logs/alerts/alerts.json | Path to JSON alerts file               |
| Alert Prefix   | `wazuh.json_alert_prefix`             | `WAZUH_JSON_ALERT_PREFIX`             | `--wazuh-json-prefix`                   | {"timestamp"                       | Expected prefix of JSON alert lines    |
| Alert Suffix   | `wazuh.json_alert_suffix`             | `WAZUH_JSON_ALERT_SUFFIX`             | `--wazuh-json-suffix`                   | }                                  | Expected suffix of JSON alert lines    |
| Poll Interval  | `wazuh.json_alert_file_poll_interval` | `WAZUH_JSON_ALERT_FILE_POLL_INTERVAL` | `--wazuh-json-alert-file-poll-interval` | 1.0                                | Interval between file checks (seconds) |
| Max Retries    | `wazuh.max_retries`                   | `WAZUH_MAX_RETRIES`                   | `--wazuh-max-retries`                   | 5                                  | Maximum number of retries              |
| Retry Interval | `wazuh.retry_interval`                | `WAZUH_RETRY_INTERVAL`                | `--wazuh-retry-interval`                | 5                                  | Interval between retries (seconds)     |

#### Kafka Configuration

| Option                 | YAML Key                       | Environment Variable           | CLI Argument                     | Default   | Description                        |
| ---------------------- | ------------------------------ | ------------------------------ | -------------------------------- | --------- | ---------------------------------- |
| Timeout                | `kafka.timeout`                | `KAFKA_TIMEOUT`                | `--kafka-timeout`                | 60        | Kafka request timeout (seconds)    |
| Retry Interval         | `kafka.retry_interval`         | `KAFKA_RETRY_INTERVAL`         | `--kafka-retry-interval`         | 5         | Interval between retries (seconds) |
| Connection Retries     | `kafka.connection_max_retries` | `KAFKA_CONNECTION_MAX_RETRIES` | `--kafka-connection-max-retries` | 5         | Maximum connection retry attempts  |
| Send Retries           | `kafka.send_max_retries`       | `KAFKA_SEND_MAX_RETRIES`       | `--kafka-send-max-retries`       | 5         | Maximum send retry attempts        |
| Max Wait Time          | `kafka.max_wait_time`          | `KAFKA_MAX_WAIT_TIME`          | `--kafka-max-wait-time`          | 60        | Maximum wait time (seconds)        |
| Admin Timeout          | `kafka.admin_timeout`          | `KAFKA_ADMIN_TIMEOUT`          | `--kafka-admin-timeout`          | 10        | Admin operation timeout (seconds)  |
| Service Retry Interval | `kafka.service_retry_interval` | `KAFKA_SERVICE_RETRY_INTERVAL` | `--kafka-service-retry-interval` | 5         | Service retry interval (seconds)   |
| Producer Config        | `kafka.producer_config`        | `KAFKA_PRODUCER_CONFIG`        | `--kafka-producer-config`        | See below | Kafka producer configuration       |

Default producer configuration:

```yaml
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
```

#### Logging Configuration

| Option          | YAML Key        | Environment Variable  | CLI Argument            | Default                           | Description                                           |
| --------------- | --------------- | --------------------- | ----------------------- | --------------------------------- | ----------------------------------------------------- |
| Console Logging | `log.console`   | `LOG_CONSOLE_ENABLED` | `--log-console-enabled` | true                              | Enable console logging                                |
| Log File        | `log.file_path` | `LOG_FILE_PATH`       | `--log-file-path`       | /opt/wazuh-dfn/logs/wazuh-dfn.log | Path to log file                                      |
| Log Interval    | `log.interval`  | `LOG_INTERVAL`        | `--log-interval`        | 600                               | Statistics logging interval (seconds)                 |
| Log Level       | `log.level`     | `LOG_LEVEL`           | `--log-level`           | INFO                              | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |

#### Miscellaneous Configuration

| Option         | YAML Key           | Environment Variable | CLI Argument         | Default | Description                          |
| -------------- | ------------------ | -------------------- | -------------------- | ------- | ------------------------------------ |
| Worker Threads | `misc.num_workers` | `MISC_NUM_WORKERS`   | `--misc-num-workers` | 10      | Number of worker threads             |
| Own Network    | `misc.own_network` | `MISC_OWN_NETWORK`   | `--misc-own-network` | None    | Own network CIDR notation (optional) |

### Configuration Examples

#### Using Environment Variables

```bash
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
```

#### Using Command Line Arguments

```bash
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
```

#### Using YAML Configuration

```yaml
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
```

## Service Setup

### Rocky Linux 9 and Ubuntu 24.04

1. Create a systemd service file:

```bash
sudo nano /etc/systemd/system/wazuh-dfn.service
```

2. Add the following content:

```ini
[Unit]
Description=Wazuh DFN Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/wazuh-dfn/venv/bin/wazuh-dfn -c /opt/wazuh-dfn/config/config.yaml
WorkingDirectory=/opt/wazuh-dfn
User=wazuh
Group=wazuh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Set appropriate permissions:

```bash
sudo chown -R wazuh:wazuh /opt/wazuh-dfn
sudo chmod 750 /opt/wazuh-dfn
sudo chmod 640 /opt/wazuh-dfn/config/config.yaml
sudo chmod 600 /opt/wazuh-dfn/certs/*
```

4. Start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-dfn
sudo systemctl start wazuh-dfn
```

## Monitoring

- Check service status:

```bash
sudo systemctl status wazuh-dfn
```

- View logs:

```bash
sudo tail -f /opt/wazuh-dfn/logs/wazuh-dfn.log
```

## Troubleshooting

1. Check virtualenv activation:

```bash
source /opt/wazuh-dfn/venv/bin/activate
python -V  # Should show Python 3.12.x
```

2. Verify Wazuh alert file permissions:

```bash
sudo ls -l /var/ossec/logs/alerts/alerts.json
```

3. Check Kafka connectivity:

```bash
telnet incubator-stream.soc.dfn.de 443
```

4. Validate certificate permissions:

```bash
ls -l /opt/wazuh-dfn/certs/
```

5. Review logs for specific error messages:

```bash
sudo tail -n 100 /opt/wazuh-dfn/logs/wazuh-dfn.log
```

## Support

For technical support or questions, please contact:

- DFN-CERT Services GmbH for Kafka-related issues
- Your local Wazuh support for agent-related questions

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
