Troubleshooting
===============

This guide will help you diagnose and resolve common issues with the wazuh-dfn service.

Monitoring
----------

-  Check service status:

.. code:: bash

   sudo systemctl status wazuh-dfn

-  View logs:

.. code:: bash

   sudo tail -f /opt/wazuh-dfn/logs/wazuh-dfn.log
   
   # Or with journalctl if using systemd:
   sudo journalctl -fu wazuh-dfn

Common Issues and Solutions
--------------------------

Startup Issues
~~~~~~~~~~~~~

1. **Service fails to start**

   Check for configuration errors:
   
   .. code:: bash
   
      # Run with print-config-only to validate configuration
      sudo -u wazuh /opt/wazuh-dfn/venv/bin/wazuh-dfn --print-config-only --config /opt/wazuh-dfn/config/config.toml
      
      # Check logs for specific errors
      sudo tail -n 100 /opt/wazuh-dfn/logs/wazuh-dfn.log

2. **Python version errors**

   Verify Python version:
   
   .. code:: bash
   
      # Check Python version in virtualenv
      source /opt/wazuh-dfn/venv/bin/activate
      python -V  # Should show Python 3.12.x or later
      
      # If incorrect, recreate virtualenv with correct Python version
      python3.12 -m venv /opt/wazuh-dfn/venv --clear

Connection Issues
~~~~~~~~~~~~~~~~~

1. **Wazuh socket connection failures**

   Check socket path and permissions:
   
   .. code:: bash
   
      # Verify socket exists
      sudo ls -l /var/ossec/queue/sockets/queue
      
      # Verify socket permissions
      sudo ls -la /var/ossec/queue/sockets/
      
      # Make sure wazuh user can access the socket
      sudo usermod -a -G wazuh wazuh

2. **Kafka connectivity issues**

   Test connection to Kafka broker:
   
   .. code:: bash
   
      # Basic connectivity test
      telnet kafka.example.org 443
      
      # Advanced test with kcat/kafkacat
      kcat -b kafka.example.org:443 -X security.protocol=ssl \
           -X ssl.ca.location=/opt/wazuh-dfn/certs/dfn-ca.pem \
           -X ssl.certificate.location=/opt/wazuh-dfn/certs/dfn-cert.pem \
           -X ssl.key.location=/opt/wazuh-dfn/certs/dfn-key.pem \
           -L

3. **Certificate issues**

   Validate certificate permissions and expiration:
   
   .. code:: bash
   
      # Check certificate permissions
      ls -l /opt/wazuh-dfn/certs/
      
      # Check certificate expiration
      openssl x509 -enddate -noout -in /opt/wazuh-dfn/certs/dfn-cert.pem
      
      # Verify certificate chain
      openssl verify -CAfile /opt/wazuh-dfn/certs/dfn-ca.pem /opt/wazuh-dfn/certs/dfn-cert.pem

Alert Processing Issues
~~~~~~~~~~~~~~~~~~~~~~

1. **No alerts being processed**

   Check alert file and permissions:
   
   .. code:: bash
   
      # Verify alert file exists and is being updated
      sudo ls -la /var/ossec/logs/alerts/alerts.json
      sudo tail -f /var/ossec/logs/alerts/alerts.json
      
      # Check if wazuh user can read the file
      sudo -u wazuh cat /var/ossec/logs/alerts/alerts.json

2. **Alerts queued but not sent**
   
   Check Kafka connection and worker status:
   
   .. code:: bash
   
      # Look for specific error patterns in logs
      grep "Error" /opt/wazuh-dfn/logs/wazuh-dfn.log
      grep "Kafka" /opt/wazuh-dfn/logs/wazuh-dfn.log
      
      # Check for failed alerts if storage is enabled
      ls -la /opt/wazuh-dfn/failed-alerts/

Asyncio-Specific Issues
~~~~~~~~~~~~~~~~~~~~~~

1. **Task cancellation warnings**

   When you see task cancellation warnings in logs, it's usually during shutdown. If they appear during normal operation:
   
   .. code:: bash
   
      # Look for task-related errors
      grep "task" /opt/wazuh-dfn/logs/wazuh-dfn.log
      
      # Check for worker errors
      grep "worker" /opt/wazuh-dfn/logs/wazuh-dfn.log

2. **High CPU usage**

   May indicate infinite loops or blocking operations in asyncio context:
   
   .. code:: bash
   
      # Monitor CPU usage
      top -p $(pgrep -f wazuh-dfn)
      
      # Adjust worker count to match your system's CPU cores
      # Edit in config.toml:
      # [misc]
      # num_workers = <number_of_cores>

3. **Queue overflow warnings**

   Indicates alert processing can't keep up with incoming volume:
   
   .. code:: bash
   
      # Check for overflow messages
      grep "overflow" /opt/wazuh-dfn/logs/wazuh-dfn.log
      
      # Increase workers or queue size in config.toml
      # [misc]
      # num_workers = 20  # Increase for more parallel processing
      # [wazuh]
      # json_alert_queue_size = 200000  # Increase queue capacity

Performance Tuning
-----------------

1. **Increasing throughput**

   Optimize for high-volume environments:
   
   .. code-block:: text
   
      # config.toml
      [misc]
      num_workers = 20  # More workers for parallel processing
      
      [wazuh]
      json_alert_queue_size = 200000  # Larger queue
      json_alert_file_poll_interval = 0.5  # More frequent checks
      
      [kafka]
      producer_config = { "batch.size": 32768, "linger.ms": 5 }  # Tune Kafka batching

2. **Reducing memory usage**

   Optimize for resource-constrained environments:
   
   .. code:: toml
   
      # config.toml
      [misc]
      num_workers = 4  # Fewer workers
      
      [wazuh]
      json_alert_queue_size = 50000  # Smaller queue
      json_alert_file_poll_interval = 2.0  # Less frequent checks
      
      [log]
      interval = 1800  # Reduce logging frequency

Diagnostic Procedures
--------------------

1. Run with detailed logging:

   .. code:: bash

      sudo -u wazuh /opt/wazuh-dfn/venv/bin/wazuh-dfn --log-level DEBUG --config /opt/wazuh-dfn/config/config.toml

2. Verify environment variables:

   .. code:: bash

      # For systemd service
      sudo systemctl show wazuh-dfn -p Environment
      
      # For troubleshooting
      env | grep -E 'DFN_|WAZUH_|KAFKA_|LOG_|MISC_'

3. Check for memory leaks:

   .. code:: bash

      # Watch memory usage over time
      watch -n 5 'ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem | grep wazuh-dfn'

4. Test alert processing manually:

   .. code:: bash

      # Process a single alert file for testing
      sudo -u wazuh /opt/wazuh-dfn/venv/bin/wazuh-dfn --wazuh-json-alert-file /path/to/test_alert.json
