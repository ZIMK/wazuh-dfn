About
=========

The ``wazuh-dfn`` is a specialized daemon that integrates Wazuh with
DFN-CERT services. It monitors Wazuh alert files and forwards relevant
security events to the DFN SOC (Security Operations Center) for advanced
analysis and threat detection.

Features
--------

-  Efficient polling of Wazuh JSON alert file
-  Processing of critical Windows security events:

   -  Failed login attempts (4625)
   -  System audit policy changes (4719)
   -  Special privileges assigned to new logon (4672)
   -  User account creation (4720)
   -  Security log cleared (1102)
   -  And more…

-  Fail2Ban alert processing
-  Secure communication with DFN SOC via Kafka
-  Multi-threaded architecture for efficient processing
-  Built-in monitoring and statistics

How It Works
------------

The daemon operates using three main components:

1. **Alert File Watcher**: Efficiently polls the Wazuh JSON alert file
   for new alerts. It tracks file position and handles file rotation,
   ensuring no alerts are missed. The watcher:

   -  Reads alerts line by line from the JSON alert file
   -  Handles file truncation and rotation automatically
   -  Uses efficient buffered reading for optimal performance
   -  Maintains file position between reads
   -  Provides robust error handling for file access issues

2. **Alert Analysis Workers**: Multiple worker threads process queued
   alerts in parallel. They:

   -  Filter relevant security events
   -  Transform Windows events to XML schema
   -  Add RFC 5424 priority to Fail2Ban messages
   -  Forward processed alerts to DFN SOC via Kafka

3. **System Monitor**: Tracks and logs system metrics including:

   -  Queue usage and processing rates
   -  Memory consumption
   -  File processing statistics
   -  Kafka producer health
   -  Worker thread status
  