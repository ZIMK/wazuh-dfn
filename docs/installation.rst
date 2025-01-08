Installation
============

Prerequisites
-------------

-  Python 3.12
-  Wazuh manager installed
-  DFN-CERT membership and valid certificates
-  Access to DFN SOC Kafka broker

Installation
------------

   **Note**: The service will run as the ``wazuh`` user, so all
   directories and files must be owned by this user.

Rocky Linux 9
~~~~~~~~~~~~~

.. code:: bash

   # Install system dependencies
   sudo dnf update
   sudo dnf install python3.12 python3.12-pip

   # Create installation directory
   sudo mkdir -p /opt/wazuh-dfn
   sudo chown wazuh:wazuh /opt/wazuh-dfn

   # Create virtual environment
   python3.12 -m virtualenv /opt/wazuh-dfn/venv

   # Install wazuh-dfn (if you have the package uploaded to a local repository)
   sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh-dfn

   # If curl and jq are installed you can download and install latest release file with:
   curl -s https://api.github.com/repos/ZIMK/wazuh-dfn/releases/latest | jq --raw-output '.assets[1] | .browser_download_url' | xargs curl -L -o wazuh_dfn-latest.tar.gz
   sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh_dfn-latest.tar.gz

Ubuntu 24.04
~~~~~~~~~~~~

.. code:: bash

   # Install system dependencies
   sudo apt update
   sudo apt install python3.12 python3.12-venv python3.12-dev gcc

   # Create installation directory
   sudo mkdir -p /opt/wazuh-dfn
   sudo chown wazuh:wazuh /opt/wazuh-dfn

   # Create virtual environment
   python3.12 -m venv /opt/wazuh-dfn/venv

   # Install wazuh-dfn (if you have the package uploaded to a local repository)
   sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh-dfn

   # If curl and jq are installed you can download and install latest release file with:
   curl -s https://api.github.com/repos/ZIMK/wazuh-dfn/releases/latest | jq --raw-output '.assets[1] | .browser_download_url' | xargs curl -L -o wazuh_dfn-latest.tar.gz
   sudo -u wazuh /opt/wazuh-dfn/venv/bin/pip3.12 install wazuh_dfn-latest.tar.gz

Configuration
-------------

1. Create configuration directory and copy the sample configuration:

.. code:: bash

   mkdir -p /opt/wazuh-dfn/{config,certs,logs}
   curl -o /opt/wazuh-dfn/config/config.yaml https://raw.githubusercontent.com/your-repo/wazuh-dfn/main/config.sample.yaml

2. Configure the service by editing
   ``/opt/wazuh-dfn/config/config.yaml``. The DFN settings are
   **required** and must be configured:

.. code:: yaml

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

3. Important path considerations:

   -  If you have a non-default Wazuh installation, you may need to
      adjust:

      -  ``wazuh.json_alert_file``: Path to Wazuh’s JSON alert file
      -  ``wazuh.unix_socket_path``: Path to Wazuh’s Unix domain socket

   -  You can customize the log location by changing:

      -  ``log.file_path``: Where to store the wazuh-dfn service logs

   -  All other settings have sensible defaults and are optional

4. Verify your DFN certificates are in place:

.. code:: bash

   ls -l /opt/wazuh-dfn/certs/
   # Should show:
   # dfn-ca.pem
   # dfn-cert.pem
   # dfn-key.pem

Service Setup
-------------

Rocky Linux 9 and Ubuntu 24.04
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Create a systemd service file:

.. code:: bash

   sudo nano /etc/systemd/system/wazuh-dfn.service

2. Add the following content:

.. code:: ini

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

3. Set appropriate permissions:

.. code:: bash

   sudo chown -R wazuh:wazuh /opt/wazuh-dfn
   sudo chmod 750 /opt/wazuh-dfn
   sudo chmod 640 /opt/wazuh-dfn/config/config.yaml
   sudo chmod 600 /opt/wazuh-dfn/certs/*

4. Start and enable the service:

.. code:: bash

   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-dfn
   sudo systemctl start wazuh-dfn
