About
=========

The ``wazuh-dfn`` is a specialized daemon that integrates Wazuh with
DFN-CERT services. It monitors Wazuh alert files and forwards relevant
security events to the DFN SOC (Security Operations Center) for advanced
analysis and threat detection. The service is built with asyncio for efficient, 
non-blocking I/O operations, resulting in high performance and scalability.

Features
--------

-  Asynchronous processing with Python's asyncio
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
-  Concurrent processing for efficient alert handling
-  Built-in monitoring and statistics
-  Support for YAML and TOML configuration

How It Works
------------

The daemon operates using several asynchronous components:

1. **Alert File Watcher**: Efficiently monitors the Wazuh JSON alert file
   for new alerts using non-blocking I/O. It tracks file position and handles file rotation,
   ensuring no alerts are missed. The watcher:

   -  Reads alerts asynchronously from the JSON alert file
   -  Handles file truncation and rotation automatically
   -  Uses aiofiles for efficient non-blocking file operations
   -  Maintains file position between reads
   -  Provides robust error handling for file access issues

2. **Alert Processing Workers**: Multiple asynchronous tasks process queued
   alerts concurrently. They:

   -  Filter relevant security events
   -  Transform Windows events to XML schema
   -  Add RFC 5424 priority to Fail2Ban messages
   -  Forward processed alerts to DFN SOC via Kafka
   -  Process alerts in parallel without blocking the event loop

3. **Kafka Service**: Handles communication with the Kafka broker:

   -  Uses aiokafka for asynchronous Kafka operations
   -  Implements automatic reconnection and retry logic
   -  Provides TLS/SSL security for communication
   -  Handles message delivery guarantees

4. **System Monitor**: Tracks and logs system metrics including:

   -  Queue usage and processing rates
   -  Memory consumption
   -  File processing statistics
   -  Kafka producer health
   -  Worker task status

Technical Stack
--------------

- **Python**: Version 3.12 or later
- **asyncio**: For non-blocking I/O and concurrent operations
- **aiokafka**: Asynchronous Kafka client
- **aiofiles**: Asynchronous file operations
- **Pydantic**: For configuration validation
- **PDM**: Modern Python package and dependency management
