Wazuh-DFN Architecture
======================

This document describes the architecture of the wazuh-dfn integration, focusing on its asyncio-based design and component interaction.

Overview
--------

Wazuh-DFN is built as a set of asynchronous services that work together to process Wazuh alerts and forward them to DFN-CERT Kafka endpoints. The architecture is designed to be:

- **High performance**: Process large volumes of alerts with minimal overhead
- **Resilient**: Handle errors gracefully and recover from failures
- **Extensible**: Allow new alert handlers to be added easily
- **Configurable**: Support multiple configuration methods

Core Components
--------------

.. image:: ./img/architecture.png
   :alt: Architecture Diagram

Main Service Orchestrator
~~~~~~~~~~~~~~~~~~~~~~~~~

The main module (``main.py``) acts as an orchestrator that:

1. Loads and validates configuration
2. Initializes all services
3. Sets up signal handlers for graceful shutdown
4. Uses ``asyncio.TaskGroup`` to manage concurrent service tasks

The orchestrator follows modern asyncio practices:

.. code-block:: python

    async def setup_service(config: Config) -> None:
        """Set up and run the Wazuh DFN service using asyncio."""
        shutdown_event = asyncio.Event()
        alert_queue = AsyncMaxSizeQueue(maxsize=config.wazuh.json_alert_queue_size)

        # Initialize core services
        wazuh_service = WazuhService(config=config.wazuh)
        await wazuh_service.start()

        # Initialize more services...

        # Use Python 3.11+ task groups for cleaner task management
        async with asyncio.TaskGroup() as tg:
            # Start all services as concurrent tasks
            tg.create_task(kafka_service.start(), name="KafkaService")
            tg.create_task(alerts_worker_service.start(), name="AlertsWorkerService")
            tg.create_task(alerts_watcher_service.start(), name="AlertsWatcherService")
            
            # Wait until shutdown is signaled
            await shutdown_event.wait()

Services
~~~~~~~~

All services are designed to work asynchronously and can be categorized into:

Core Services
^^^^^^^^^^^^

- **WazuhService**: Handles communication with the Wazuh server

  - Manages socket connections (Unix or TCP)
  - Sends events and errors
  - Handles reconnection logic
  - Uses asyncio streams for efficient I/O

- **KafkaService**: Handles communication with Kafka

  - Uses aiokafka for asynchronous Kafka operations
  - Manages producer connections
  - Sends messages to Kafka topics
  - Validates topic existence
  - Handles TLS/SSL security
  - Implements retry logic with exponential backoff

Alert Processing Services
^^^^^^^^^^^^^^^^^^^^^^^^

- **AlertsWatcherService**: Monitors alert files for new alerts

  - Uses ``FileMonitor`` to read and parse JSON alerts
  - Adds alerts to the processing queue
  - Handles file rotation detection

- **AlertsWorkerService**: Processes alerts from the queue

  - Creates a pool of worker tasks using asyncio.TaskGroup
  - Distributes alerts to workers
  - Handles processing errors
  - Manages worker lifecycle

- **AlertsService**: Delegates alerts to specialized handlers

  - Determines the handler based on alert type
  - Coordinates processing between handlers

Auxiliary Services
^^^^^^^^^^^^^^^^^

- **LoggingService**: Handles logging and statistics

  - Configures logging
  - Periodically logs statistics
  - Monitors system resources using psutil
  - Reports queue sizes and processing rates

Specialized Handlers
~~~~~~~~~~~~~~~~~~~

- **SyslogHandler**: Processes syslog-specific alerts (e.g., fail2ban)
  - Formats events according to RFC 5424
  - Filters internal IPs based on configuration
  - Sends events to Kafka and Wazuh

- **WindowsHandler**: Processes Windows event log alerts
  - Handles specific Windows event IDs
  - Formats events in Windows XML format
  - Preserves original event structure

Helper Components
~~~~~~~~~~~~~~~~

- **AsyncMaxSizeQueue**: Queue implementation with specific features:
  - Discards oldest items when full
  - Implements asynchronous put/get operations
  - Tracks discarded items and provides statistics
  - Prevents memory overflow during traffic spikes

- **FileMonitor**: Advanced file monitoring with:
  - Asynchronous file operations using aiofiles
  - Rotation detection via inode tracking
  - Partial alert handling across reads
  - Buffer management for large alerts
  - Character encoding handling

Asynchronous Flow
----------------

The asynchronous flow of the application follows these steps:

1. **Initialization**: Services are initialized and connected
2. **Alert Monitoring**: The ``FileMonitor`` reads new alerts from Wazuh alert files
3. **Queueing**: New alerts are added to the ``AsyncMaxSizeQueue``
4. **Processing**: Worker tasks process alerts from the queue 
5. **Handling**: Specialized handlers format and process alerts based on type
6. **Sending**: Processed alerts are sent to Kafka and confirmation is sent to Wazuh

This flow is fully asynchronous, allowing for:

- Concurrent processing of multiple alerts
- Non-blocking I/O operations
- Efficient use of system resources
- Graceful handling of backpressure

Asyncio Task Management
----------------------

The application uses modern asyncio patterns:

- **Task Groups**: Python 3.11+ TaskGroup for managing related tasks
- **Named Tasks**: All tasks are named for better observability
- **Cancellation Handling**: Proper handling of CancelledError
- **Lock Protection**: AsyncLock for thread-safe access to shared resources
- **Event Signaling**: AsyncEvent for coordination between services

Error Handling and Recovery
--------------------------

The architecture includes several mechanisms for error handling and recovery:

- **Reconnection Logic**: Services automatically reconnect on connection failures
- **Retry Logic**: Failed operations are retried with exponential backoff
- **Queue Management**: Overflow protection ensures system stability under load
- **Task Management**: Proper task cancellation and cleanup during shutdown
- **Failed Alert Storage**: Option to store alerts that fail processing for later analysis
- **Character Encoding Handling**: Automatic handling of encoding issues in alerts

Configuration
------------

The system supports multiple configuration methods:

- **Files**: YAML or TOML configuration files
- **Environment Variables**: For containerized environments
- **Command-line Arguments**: For direct configuration

Configuration is validated using Pydantic models with:

- Type checking and custom validators
- Certificate validation for SSL/TLS
- Automatic generation of sample configurations
- Secure handling of sensitive information

Performance Considerations
------------------------

The asyncio-based architecture provides several performance benefits:

- **Non-blocking I/O**: All I/O operations are non-blocking
- **Worker Pool**: Configurable number of worker tasks for alert processing
- **Buffer Management**: Efficient buffer management for file monitoring
- **Queue Sizing**: Configurable queue sizes to balance memory usage and throughput
- **Batching**: Message batching for efficient Kafka communication
- **Resource Monitoring**: Built-in monitoring of queue sizes and processing rates

Extension Points
--------------

To extend the system with new functionality:

1. Add new handlers in the ``handlers`` directory
2. Register them in the ``AlertsService``
3. Implement the necessary processing logic

Example handler implementation pattern:

.. code-block:: python

    class NewHandler:
        """Handler for a new alert type."""
        
        def __init__(self, kafka_service, wazuh_service):
            self.kafka_service = kafka_service
            self.wazuh_service = wazuh_service
            
        async def process_alert(self, alert: dict) -> None:
            """Process a new type of alert asynchronously."""
            if self._is_relevant_alert(alert):
                message = self._create_message(alert)
                await self.kafka_service.send_message(message)
                await self.wazuh_service.send_event(alert)
                
        def _is_relevant_alert(self, alert: dict) -> bool:
            """Determine if this alert should be processed by this handler."""
            # Implementation
            
        def _create_message(self, alert: dict) -> dict:
            """Create a message for Kafka from the alert."""
            # Implementation