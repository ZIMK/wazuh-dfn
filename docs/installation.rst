Installation
============

Prerequisites
-------------

-  Python 3.12 or later
-  Wazuh manager installed
-  DFN-CERT membership and valid certificates
-  Access to DFN SOC Kafka broker

About wazuh-dfn
--------------

The wazuh-dfn service is built with Python's asyncio for efficient, non-blocking I/O operations. This architecture provides:

- High performance alert processing with minimal overhead
- Efficient handling of large volumes of alerts
- Robust error recovery mechanisms
- Resource-efficient operation even under heavy loads

Installation Methods
------------------

There are several ways to install the wazuh-dfn service:

Using pip (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^

The simplest method is to install from PyPI using pip:

.. code-block:: bash

    python3 -m pip install wazuh-dfn

This will install the latest stable version of the service.

Install from Source with PDM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For development or to get the latest features:

.. code-block:: bash

    # Clone the repository
    git clone https://github.com/ZIMK/wazuh-dfn.git
    cd wazuh-dfn
    
    # Install PDM (Python Dependency Manager)
    python -m pip install --upgrade pip pdm
    
    # Install the project
    pdm install

Docker Container
^^^^^^^^^^^^^^^

A Docker container is available for easy deployment:

.. code-block:: bash

    docker pull zimk/wazuh-dfn:latest
    docker run -v /path/to/config:/etc/wazuh-dfn -v /path/to/certs:/opt/wazuh-dfn/certs zimk/wazuh-dfn:latest

OS-Specific Installation
-----------------------

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

The service now supports both YAML and TOML configuration formats. You can generate a sample configuration file using:

.. code-block:: bash

    # Generate sample configuration - YAML format
    /opt/wazuh-dfn/venv/bin/wazuh-dfn --generate-sample-config --output-format yaml > /opt/wazuh-dfn/config/config.yaml
    
    # Or TOML format (recommended)
    /opt/wazuh-dfn/venv/bin/wazuh-dfn --generate-sample-config --output-format toml > /opt/wazuh-dfn/config/config.toml

1. Create configuration directory if not already done:

.. code:: bash

   mkdir -p /opt/wazuh-dfn/{config,certs,logs}

2. Configure the service by editing the configuration file. The DFN settings are **required** and must be configured:

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
     num_workers: 10 # Number of worker tasks for asyncio processing 
     own_network: # Optional: Network CIDR for own network filtering (e.g. "10.0.0.0/8")

3. Important path considerations:

   -  If you have a non-default Wazuh installation, you may need to
      adjust:

      -  ``wazuh.json_alert_file``: Path to Wazuh's JSON alert file
      -  ``wazuh.unix_socket_path``: Path to Wazuh's Unix domain socket

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
   Description=Wazuh DFN Integration Service
   After=network.target wazuh-manager.service
   
   [Service]
   Type=simple
   ExecStart=/opt/wazuh-dfn/venv/bin/wazuh-dfn -c /opt/wazuh-dfn/config/config.yaml
   WorkingDirectory=/opt/wazuh-dfn
   User=wazuh
   Group=wazuh
   Restart=on-failure
   RestartSec=10
   StandardOutput=journal
   StandardError=journal
   
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

Windows Service
~~~~~~~~~~~~~~

On Windows, you can use NSSM (Non-Sucking Service Manager) to create a service:

.. code-block:: powershell

    # Install NSSM if not already installed
    # Using Chocolatey: choco install nssm
    
    # Create the service
    nssm install WazuhDFN "C:\Path\to\Python\python.exe" "-m wazuh_dfn --config C:\path\to\config.toml"
    nssm set WazuhDFN DisplayName "Wazuh DFN Integration"
    nssm set WazuhDFN Description "Forwards Wazuh alerts to DFN-CERT SOC"
    nssm set WazuhDFN Start SERVICE_AUTO_START
    
    # Start the service
    nssm start WazuhDFN

Verifying Installation
---------------------

To verify that your installation is working correctly:

1. Check the service status:

   .. code-block:: bash

       # On Linux with systemd
       sudo systemctl status wazuh-dfn
       
       # On Windows
       sc query WazuhDFN

2. Check the logs for successful startup messages:

   .. code-block:: bash

       # If configured to log to a file
       tail -f /opt/wazuh-dfn/logs/wazuh-dfn.log
       
       # Or check the journal on systemd systems
       sudo journalctl -fu wazuh-dfn

Next Steps
---------

For detailed configuration options, refer to the :doc:`configuration` section to further customize your wazuh-dfn instance.
