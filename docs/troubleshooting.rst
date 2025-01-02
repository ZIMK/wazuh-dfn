Troubleshooting
===============

Monitoring
----------

-  Check service status:

.. code:: bash

   sudo systemctl status wazuh-dfn

-  View logs:

.. code:: bash

   sudo tail -f /opt/wazuh-dfn/logs/wazuh-dfn.log

Troubleshooting
---------------

1. Check virtualenv activation:

.. code:: bash

   source /opt/wazuh-dfn/venv/bin/activate
   python -V  # Should show Python 3.12.x

2. Verify Wazuh alert file permissions:

.. code:: bash

   sudo ls -l /var/ossec/logs/alerts/alerts.json

3. Check Kafka connectivity:

.. code:: bash

   telnet incubator-stream.soc.dfn.de 443

4. Validate certificate permissions:

.. code:: bash

   ls -l /opt/wazuh-dfn/certs/

5. Review logs for specific error messages:

.. code:: bash

   sudo tail -n 100 /opt/wazuh-dfn/logs/wazuh-dfn.log
