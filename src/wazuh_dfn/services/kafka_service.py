"""Kafka service module for handling Kafka operations."""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import ssl
import time
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from wazuh_dfn.health.event_service import HealthEventService
    from wazuh_dfn.health.models import KafkaInternalStatsData

from aiokafka import AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient
from aiokafka.helpers import create_ssl_context

from wazuh_dfn.config import DFNConfig, KafkaConfig
from wazuh_dfn.health.builders import KafkaPerformanceBuilder
from wazuh_dfn.health.models import KafkaPerformanceData
from wazuh_dfn.services.wazuh_service import WazuhService

LOGGER = logging.getLogger(__name__)


class KafkaErrorCode(StrEnum):
    """Enumeration of Kafka error codes."""

    TIMED_OUT = auto()
    TOPIC_AUTHORIZATION_FAILED = auto()
    BROKER_NOT_AVAILABLE = auto()


class KafkaMessage(TypedDict, total=False):
    """Type definition for a Kafka message."""

    # Required fields
    timestamp: str
    event_format: str
    event_forward: bool
    event_parser: str
    event_source: str
    body: str

    # Optional fields
    event_raw: str
    hostName: str
    structuredData: str
    appName: str
    appInst: str
    procId: str
    facility: str
    priority: int
    severity: int
    data: dict[str, Any]

    # Store the original alert for later use
    context_alert: dict[str, Any]


class KafkaResponse(TypedDict):
    """Type definition for a Kafka response."""

    success: bool
    topic: str


class KafkaService:
    """Service for handling Kafka operations.

    This class encapsulates all Kafka-related operations and configuration.
    It follows the principle of least privilege by only accessing
    the configuration it needs.
    """

    def __init__(
        self,
        config: KafkaConfig,
        dfn_config: DFNConfig,
        wazuh_service: WazuhService,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Initialize KafkaService.

        Args:
            config: Kafka configuration
            dfn_config: DFN configuration
            wazuh_handler: WazuhService instance
            shutdown_event: Event to signal shutdown

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Validation is handled by Pydantic automatically
        self.config = config
        self.dfn_config = dfn_config
        self.wazuh_service = wazuh_service
        self.shutdown_event = shutdown_event
        self.producer = None
        self._lock = asyncio.Lock()
        self._connection_lock = asyncio.Lock()

        # Reference to the logging service (will be set later)
        self._logging_service = None
        self._health_event_service: HealthEventService | None = None

        # Track message count for diagnostics
        self._metrics = {
            "total_sent": 0,
            "errors": 0,
            "slow_operations": 0,
        }

    def set_logging_service(self, logging_service) -> None:
        """Set the logging service reference for performance logging.

        Args:
            logging_service: The logging service instance
        """
        self._logging_service = logging_service

    def set_health_event_service(self, health_event_service: HealthEventService) -> None:
        """Set the health event service for direct event pushing.

        Args:
            health_event_service: The health event service instance
        """
        self._health_event_service = health_event_service

    def _create_custom_ssl_context(self) -> ssl.SSLContext:
        """Create a custom SSL context for more control over SSL/TLS settings.

        Returns:
            ssl.SSLContext: Configured SSL context
        """
        context = create_ssl_context(
            certfile=self.dfn_config.dfn_cert,  # Signed certificate
            keyfile=self.dfn_config.dfn_key,  # Private Key file of `certfile` certificate
        )
        LOGGER.info(f"Created custom SSL context for {self.dfn_config.dfn_id}: {context}")

        return context

    def _ensure_datetime_consistency(self) -> None:
        """Ensure datetime objects in certificates are consistently timezone-aware.

        This helps prevent "can't compare offset-naive and offset-aware datetimes" errors
        during certificate validation.
        """
        try:
            # Set the default timezone for datetime objects if needed
            if hasattr(datetime, "timezone") and datetime.timezone:
                datetime.datetime.now(datetime.UTC)  # This creates a timezone-aware datetime
        except Exception as e:
            LOGGER.warning(f"Error setting up timezone consistency: {e}")

    async def _create_producer(self) -> None:
        """Create a new Kafka producer instance with enhanced SSL security."""
        start_time = time.time()

        if self.producer:
            try:
                await self.producer.stop()  # type: ignore[]
            except Exception as e:
                LOGGER.warning(f"Error closing existing Kafka producer: {e}")
            self.producer = None

        # Before creating the producer, validate certificates
        if self.dfn_config.dfn_cert and self.dfn_config.dfn_key:
            LOGGER.info(
                f"Validating certificates for {self.dfn_config.dfn_id}. "
                f"ca: {self.dfn_config.dfn_ca}, cert: {self.dfn_config.dfn_cert}, key: {self.dfn_config.dfn_key}"
            )
            try:
                # Ensure datetime consistency before certificate validation
                self._ensure_datetime_consistency()
                self.dfn_config.validate_certificates()
                ssl_context = self._create_custom_ssl_context()
                LOGGER.info("Certificates validated successfully.")
            except Exception as e:
                if "can't compare offset-naive and offset-aware datetimes" in str(e):
                    LOGGER.error(f"Certificate datetime comparison error: {e}. Using default SSL context.")
                    # Create a more basic SSL context as fallback
                    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_context.load_cert_chain(certfile=self.dfn_config.dfn_cert, keyfile=self.dfn_config.dfn_key)
                    ssl_context.load_verify_locations(cafile=self.dfn_config.dfn_ca)
                else:
                    LOGGER.error(f"Certificate validation failed: {e}")
                    raise
        else:
            ssl_context = None

        # Get producer configuration directly from config class - now includes all optimizations
        producer_config = self.config.get_producer_config(self.dfn_config)

        # Remove bootstrap_servers from producer_config since it's passed separately
        bootstrap_servers = producer_config.pop("bootstrap_servers", self.dfn_config.dfn_broker)
        security_protocol = producer_config.pop("security_protocol", "SSL" if ssl_context else None)

        LOGGER.info(
            f"Creating Kafka producer for {self.dfn_config.dfn_id} with bootstrap servers: {bootstrap_servers}"
            f" and security protocol: {security_protocol}"
        )
        LOGGER.debug(f"Producer config: {producer_config}")
        LOGGER.debug(f"SSL context: {ssl_context}")
        LOGGER.debug(f"Security protocol: {security_protocol}")

        # Create aiokafka producer
        self.producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            security_protocol=security_protocol if security_protocol else "PLAINTEXT",
            ssl_context=ssl_context,
            **producer_config,
        )

        try:
            LOGGER.info(f"Starting Kafka producer for {self.dfn_config.dfn_id}...")
            await self.producer.start()
            LOGGER.info(f"Kafka producer started successfully in {time.time() - start_time:.2f}s")
        except Exception as e:
            LOGGER.error(f"Failed to start Kafka producer after {time.time() - start_time:.2f}s: {e}")
            if "Client certificate not issued by the provided CA" in str(e):
                LOGGER.error(f"SSL certificate error: {e}")
            raise

    async def _test_connection(self) -> None:
        """Verify that configured topic exists in Kafka cluster asynchronously.

        Checks the configured topic exists in the broker using admin client
        with configuration directly from KafkaConfig.

        Raises:
            Exception: If topic verification fails
        """
        # Create SSL context if needed
        ssl_context = (
            self._create_custom_ssl_context() if (self.dfn_config.dfn_cert and self.dfn_config.dfn_key) else None
        )

        # Get admin client configuration directly from config
        admin_config = self.config.get_admin_config(self.dfn_config)

        # Remove bootstrap_servers from admin_config since it's passed separately
        bootstrap_servers = admin_config.pop("bootstrap_servers", self.dfn_config.dfn_broker)
        security_protocol = admin_config.pop("security_protocol", "SSL" if ssl_context else None)

        # Create admin client
        admin_client = AIOKafkaAdminClient(
            bootstrap_servers=bootstrap_servers,
            security_protocol=security_protocol,
            ssl_context=ssl_context,
            **admin_config,
        )

        try:
            await admin_client.start()
            topics = await admin_client.list_topics()  # This will raise an error if the connection fails

            if not topics:
                raise Exception("Failed to retrieve available topics")  # NOSONAR

            LOGGER.info(f"Topic info for {self.dfn_config.dfn_id}: {topics}")

            if self.dfn_config.dfn_id not in topics:
                LOGGER.error(f"Configured topic '{self.dfn_config.dfn_id}' not found in available topics!")
                raise Exception(f"Topic '{self.dfn_config.dfn_id}' not found in Kafka cluster")  # NOSONAR

        except Exception as e:
            if "Client certificate not issued by the provided CA" in str(e):
                LOGGER.error(f"SSL certificate error: {e}")
            raise

        finally:
            await admin_client.close()

    async def _handle_connect_error(self, e: Exception, retry_count: int, max_retries: int) -> None:
        """Handle connection error with appropriate logging and error reporting.

        Args:
            e: Exception that occurred
            retry_count: Current retry attempt number
            max_retries: Maximum number of retries allowed
        """
        wait_time = min(self.config.retry_interval * (2**retry_count), self.config.max_wait_time)
        error_msg = (
            f"Kafka broker not available. Attempt {retry_count}/{max_retries}."
            f" Retrying in {wait_time} seconds... Error: {e}"
        )
        LOGGER.error(error_msg)

        await self.wazuh_service.send_error(
            {
                "error": 503,
                "description": f"Kafka broker not available. Attempt {retry_count}/{max_retries}. Retrying...",
            }
        )
        if self.shutdown_event.is_set():
            return

        await asyncio.sleep(wait_time)

    async def connect(self) -> None:
        """Connect to Kafka broker asynchronously."""
        async with self._connection_lock:  # Ensure only one task can attempt connection at a time
            retry_count = 0
            max_retries = self.config.connection_max_retries

            while not self.shutdown_event.is_set() and retry_count < max_retries:
                # First try-catch block for creating the producer
                try:
                    await self._create_producer()
                except Exception as e:
                    retry_count += 1
                    LOGGER.error(f"Error creating Kafka producer: {e}")
                    await self._handle_connect_error(e, retry_count, max_retries)
                    continue

                # Second try-catch block for testing the connection
                try:
                    # Test the connection by creating an admin client
                    await self._test_connection()

                    LOGGER.info("Connected to Kafka successfully.")
                    return
                except Exception as e:
                    retry_count += 1
                    LOGGER.error(f"Error testing Kafka connection: {e}")
                    await self._handle_connect_error(e, retry_count, max_retries)

            if retry_count >= max_retries:
                LOGGER.error("Max retry attempts reached. Failed to connect to Kafka broker.")
                raise ConnectionError("Failed to connect to Kafka broker after maximum retry attempts")

    async def _on_send_success(self, record_metadata) -> None:
        """Handle successful message send.

        Args:
            record_metadata: Metadata about the sent message
        """
        LOGGER.debug(
            f"Alert sent to topic {record_metadata.topic} partition {record_metadata.partition} "
            f"offset {record_metadata.offset}"
        )

    async def _on_send_error(self, exc) -> None:
        """Handle message send error.

        Args:
            exc: Exception that occurred
        """
        error_msg = (
            f"Failed to send alert to Kafka: {exc.str()}"
            if hasattr(exc, "str")
            else f"Failed to send alert to Kafka: {exc}"
        )
        LOGGER.error(error_msg)
        await self.wazuh_service.send_error({"error": 503, "description": error_msg})

    async def _handle_producer_cleanup(self) -> None:
        """Clean up Kafka producer safely asynchronously."""
        if self.producer:
            try:
                await self.producer.stop()  # type: ignore[]
            except Exception as close_error:
                LOGGER.warning(f"Error closing Kafka producer: {close_error}")
            self.producer = None

    async def _handle_retry_wait(self, retry_count: int, max_retries: int) -> None:
        """Handle retry wait logic asynchronously.

        Args:
            retry_count: Current retry attempt number
            max_retries: Maximum number of retries allowed
        """
        wait_time = min(self.config.retry_interval * (2**retry_count), self.config.max_wait_time)
        LOGGER.info(f"Retrying in {wait_time} seconds... (Attempt {retry_count}/{max_retries})")
        await asyncio.sleep(wait_time)

    async def _send_message_once(self, message: KafkaMessage) -> KafkaResponse | None:
        """Attempt to send a message once asynchronously.

        Args:
            message: Message to send

        Returns:
            Optional[KafkaResponse]: Response dictionary if successful, None if failed

        Raises:
            Exception: If there is an error
        """
        async with self._lock:  # Ensure thread-safe access to producer
            start_time = time.time()
            stage_times = {}

            if not self.producer:
                connect_start = time.time()
                await self.connect()
                stage_times["connect"] = time.time() - connect_start

            # Create copy of message and remove context_alert
            prep_start = time.time()
            message_sent = message.copy()
            if "context_alert" in message_sent:
                del message_sent["context_alert"]
            stage_times["prep"] = time.time() - prep_start

            # Convert message to JSON string and encode
            encode_start = time.time()
            message_bytes = json.dumps(message_sent).encode("utf-8")
            stage_times["encode"] = time.time() - encode_start

            # Send message asynchronously
            send_start = time.time()
            await self.producer.send_and_wait(
                topic=self.dfn_config.dfn_id, value=message_bytes, timestamp_ms=int(time.time() * 1000)
            )
            stage_times["send"] = time.time() - send_start

            total_time = time.time() - start_time
            self._metrics["total_sent"] += 1

            # Record performance data
            performance_data: KafkaPerformanceData = (
                KafkaPerformanceBuilder.create(total_time)
                .with_prep_time(stage_times.get("prep", 0.0))
                .with_encode_time(stage_times.get("encode", 0.0))
                .with_send_time(stage_times.get("send", 0.0))
                .with_message_size(len(message_bytes))
                .with_topic(str(self.dfn_config.dfn_id))
                .build()
            )

            if self._health_event_service:
                await self._health_event_service.push_kafka_performance(performance_data)
            elif self._logging_service:
                await self._logging_service.record_kafka_performance(performance_data)

            return KafkaResponse(
                success=True,
                topic=str(self.dfn_config.dfn_id),
            )

    async def send_message(self, message: KafkaMessage) -> KafkaResponse | None:
        """Send message to Kafka broker asynchronously.

        Args:
            message: Message to send

        Returns:
            Optional[KafkaResponse]: Response dictionary if successful, None if failed
        """
        retry_count = 0
        max_retries = self.config.send_max_retries

        while retry_count < max_retries:
            try:
                return await self._send_message_once(message)

            except Exception as e:
                LOGGER.error(f"Error sending message to Kafka: {e}")
                await self.wazuh_service.send_error(
                    {
                        "error": 503,
                        "description": (
                            f"Kafka error. Attempt {retry_count + 1}/{max_retries}. Reinitializing producer."
                        ),
                    }
                )

                self._metrics["errors"] += 1

                async with self._lock:  # Thread-safe producer cleanup
                    await self._handle_producer_cleanup()

                retry_count += 1
                if retry_count < max_retries:
                    await self._handle_retry_wait(retry_count, max_retries)
                    continue
                return None

        LOGGER.error("Max retry attempts reached. Failed to send message to Kafka.")
        return None

    async def start(self) -> None:
        """Start the Kafka service and keep running until shutdown."""
        while not self.shutdown_event.is_set():
            try:
                if not self.producer:
                    await self.connect()

                # Keep running until shutdown or error
                while not self.shutdown_event.is_set():
                    await asyncio.sleep(1)

            except Exception as e:
                LOGGER.error(f"Error in Kafka service: {e}", exc_info=True)
                await asyncio.sleep(self.config.service_retry_interval)  # Wait before retry

        # Cleanup on shutdown
        LOGGER.info("Shutting down Kafka service...")
        await self.stop()

    async def stop(self) -> None:
        """Stop the Kafka service and cleanup resources."""
        try:
            # Stop the producer
            if self.producer:
                await self.producer.stop()  # type: ignore[]
                self.producer = None
                LOGGER.info("Kafka producer stopped successfully")

            # Log final metrics
            LOGGER.info(
                f"Kafka final stats: {self._metrics['total_sent']} total messages sent "
                f"{self._metrics['errors']} errors, {self._metrics['slow_operations']} slow operations"
            )
        except Exception as e:
            LOGGER.error(f"Error stopping Kafka producer: {e}")

    # Protocol implementation methods for health monitoring

    def get_health_status(self) -> bool:
        """Check if the service is healthy and operational.

        Returns:
            bool: True if service is healthy, False otherwise
        """
        return self.is_connected()

    def get_kafka_stats(self) -> KafkaInternalStatsData:
        """Get internal Kafka performance statistics.

        Returns:
            KafkaInternalStatsData: Kafka performance metrics
        """
        return {
            "slow_operations": self._metrics.get("slow_operations", 0),
            "total_operations": self._metrics.get("total_sent", 0),
            "last_slow_operation_time": 0.0,  # Would need to track this
            "max_operation_time": 0.0,  # Would need to track this
            "recent_stage_times": [],  # Would need to track recent slow operations
        }

    def is_connected(self) -> bool:
        """Check if Kafka connection is active.

        Returns:
            bool: True if connected, False otherwise
        """
        return self.producer is not None

    def get_connection_info(self) -> dict[str, Any]:
        """Get Kafka connection information.

        Returns:
            dict[str, Any]: Connection details
        """
        return {
            "bootstrap_servers": self.dfn_config.dfn_broker,
            "timeout": self.config.timeout,
            "compression_type": self.config.compression_type,
            "connected": self.is_connected(),
        }

    def get_last_error(self) -> str | None:
        """Get the last error message if any.

        Returns:
            str | None: Last error message or None
        """
        # Would need to implement error tracking
        return None

    def get_service_metrics(self) -> dict[str, Any]:
        """Get comprehensive service metrics.

        Returns:
            dict[str, Any]: Service metrics data
        """
        return {
            "health_status": self.get_health_status(),
            "kafka_stats": self.get_kafka_stats(),
            "connection_info": self.get_connection_info(),
            "last_error": self.get_last_error(),
        }
