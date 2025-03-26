"""Kafka service module for handling Kafka operations."""

import json
import logging
import threading
import time
from .wazuh_service import WazuhService
from confluent_kafka import KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient
from enum import StrEnum, auto
from typing import Any
from wazuh_dfn.config import DFNConfig, KafkaConfig
from wazuh_dfn.validators import DFNConfigValidator, KafkaConfigValidator

LOGGER = logging.getLogger(__name__)


class KafkaErrorCode(StrEnum):
    """Enumeration of Kafka error codes."""

    TIMED_OUT = auto()
    TOPIC_AUTHORIZATION_FAILED = auto()
    BROKER_NOT_AVAILABLE = auto()


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
        wazuh_handler: WazuhService,
        shutdown_event: threading.Event,
    ) -> None:
        """Initialize KafkaService.

        Args:
            config: Kafka-specific configuration
            dfn_config: DFN configuration containing broker and SSL settings
            wazuh_handler: Service for Wazuh operations
            shutdown_event: Event to signal shutdown

        Raises:
            ConfigValidationError: If configuration validation fails
        """
        # Validate both configs
        KafkaConfigValidator.validate(config)
        DFNConfigValidator.validate(dfn_config)

        self.config = config
        self.dfn_config = dfn_config
        self.wazuh_handler = wazuh_handler
        self.shutdown_event = shutdown_event
        self.producer: Producer | None = None
        self._lock = threading.Lock()
        self._connection_lock = threading.Lock()

    def _create_producer(self) -> None:
        """Create a new Kafka producer instance.

        Raises:
            KafkaException: If producer creation fails
        """
        if self.producer:
            try:
                self.producer.close()
            except Exception as e:
                LOGGER.warning(f"Error closing existing Kafka producer: {e}")
            self.producer = None

        kafka_config = self.config.get_kafka_config(self.dfn_config)
        self.producer = Producer(kafka_config)

    def _test_connection(self) -> None:
        """Verify that configured topic exists in Kafka cluster.

        Raises:
            KafkaException: If topic verification fails
        """
        admin_client = AdminClient(self.config.get_kafka_config(self.dfn_config))

        cluster_metadata = admin_client.list_topics(timeout=self.config.admin_timeout)
        if not cluster_metadata.topics:
            raise KafkaException("Failed to retrieve cluster metadata")

        # Log available topics to help debug
        LOGGER.info("Available Kafka topics: %s", list(cluster_metadata.topics.keys()))
        if self.dfn_config.dfn_id not in cluster_metadata.topics:
            LOGGER.error("Configured topic '%s' not found in available topics!", self.dfn_config.dfn_id)
            raise KafkaException(f"Topic '{self.dfn_config.dfn_id}' not found in Kafka cluster")

    def _handle_connect_error(self, e: Exception, retry_count: int, max_retries: int) -> None:
        """Handle connection error with appropriate logging and error reporting.

        Args:
            e: Exception that occurred
            retry_count: Current retry attempt number
            max_retries: Maximum number of retries allowed
        """
        wait_time = min(self.config.retry_interval * (2**retry_count), self.config.max_wait_time)
        if isinstance(e, KafkaException):
            LOGGER.error(
                f"Kafka broker not available. Attempt {retry_count}/{max_retries}. Retrying in {wait_time} seconds... Error: {e}"
            )
            self.wazuh_handler.send_error(
                {
                    "error": 503,
                    "description": f"Kafka broker not available. Attempt {retry_count}/{max_retries}. Retrying...",
                }
            )
        else:
            LOGGER.error(
                f"Error connecting to Kafka: {e}. Attempt {retry_count}/{max_retries}. Retrying in {wait_time} seconds..."
            )
        time.sleep(wait_time)

    def connect(self) -> None:
        """Connect to Kafka broker."""
        with self._connection_lock:  # Ensure only one thread can attempt connection at a time
            retry_count = 0
            max_retries = self.config.connection_max_retries

            while not self.shutdown_event.is_set() and retry_count < max_retries:
                try:
                    self._create_producer()

                    # Test the connection by creating an admin client
                    self._test_connection()

                    LOGGER.info("Connected to Kafka successfully.")
                    return

                except (KafkaException, Exception) as e:
                    retry_count += 1
                    self._handle_connect_error(e, retry_count, max_retries)

            if retry_count >= max_retries:
                LOGGER.error("Max retry attempts reached. Failed to connect to Kafka broker.")
                raise ConnectionError("Failed to connect to Kafka broker after maximum retry attempts")

    def _delivery_callback(self, err, msg) -> None:
        """Handle message delivery reports.

        Args:
            err: Error that occurred during delivery, if any
            msg: Message that was delivered
        """
        if err is not None:
            if err.code() == KafkaError._TIMED_OUT:
                LOGGER.error(f"Message delivery {KafkaErrorCode.TIMED_OUT}")
            elif err.code() == KafkaError._TOPIC_AUTHORIZATION_FAILED:
                LOGGER.error(f"{KafkaErrorCode.TOPIC_AUTHORIZATION_FAILED} - check topic permissions")
            elif err.code() == KafkaError._BROKER_NOT_AVAILABLE:
                LOGGER.error(f"{KafkaErrorCode.BROKER_NOT_AVAILABLE} - check broker health")
            else:
                LOGGER.error(f"Message delivery failed: {err.str()}")
            self._on_send_error(err)
        else:
            self._on_send_success(msg)

    def _on_send_success(self, record_metadata) -> None:
        """Handle successful message send.

        Args:
            record_metadata: Metadata about the sent message
        """
        LOGGER.debug(
            f"Alert sent to topic {record_metadata.topic()=} partition {record_metadata.partition()=} offset {record_metadata.offset()=}"
        )

    def _on_send_error(self, exc) -> None:
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
        self.wazuh_handler.send_error({"error": 503, "description": error_msg})

    def _handle_producer_cleanup(self) -> None:
        """Clean up Kafka producer safely."""
        if self.producer:
            try:
                self.producer.close()
            except Exception as close_error:
                LOGGER.warning(f"Error closing Kafka producer: {close_error}")
            self.producer = None

    def _handle_retry_wait(self, retry_count: int, max_retries: int) -> None:
        """Handle retry wait logic.

        Args:
            retry_count: Current retry attempt number
            max_retries: Maximum number of retries allowed
        """
        wait_time = min(self.config.retry_interval * (2**retry_count), self.config.max_wait_time)
        LOGGER.info(f"Retrying in {wait_time} seconds... (Attempt {retry_count}/{max_retries})")
        time.sleep(wait_time)

    def _send_message_once(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Attempt to send a message once.

        Args:
            message: Message to send

        Returns:
            Optional[Dict[str, Any]]: Response dictionary if successful, None if failed

        Raises:
            KafkaException: If there is a Kafka-specific error
            Exception: For any other unexpected errors
        """
        with self._lock:  # Ensure thread-safe access to producer
            if not self.producer:
                self.connect()

            # Convert message to JSON string and encode
            message_bytes = json.dumps(message).encode("utf-8")

            # Send message with delivery callback
            self.producer.produce(topic=self.dfn_config.dfn_id, value=message_bytes, callback=self._delivery_callback)

            # Wait for message to be delivered
            remaining = self.producer.flush(timeout=self.config.timeout)
            if remaining > 0:
                raise KafkaException(f"{remaining} messages still in queue after timeout")

            return {
                "success": True,
                "topic": self.dfn_config.dfn_id,
            }

    def send_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Send message to Kafka broker.

        Args:
            message: Message to send

        Returns:
            Optional[Dict[str, Any]]: Response dictionary if successful, None if failed
        """
        retry_count = 0
        max_retries = self.config.send_max_retries

        while retry_count < max_retries:
            try:
                return self._send_message_once(message)

            except KafkaException as e:
                LOGGER.error(f"Error sending message to Kafka: {e}")
                self.wazuh_handler.send_error(
                    {
                        "error": 503,
                        "description": (
                            f"Kafka error. Attempt {retry_count + 1}/{max_retries}. Reinitializing producer."
                        ),
                    }
                )
                with self._lock:  # Thread-safe producer cleanup
                    self._handle_producer_cleanup()

                retry_count += 1
                if retry_count < max_retries:
                    self._handle_retry_wait(retry_count, max_retries)
                    continue
                return None

            except Exception as e:
                LOGGER.error(f"Unexpected error sending message to Kafka: {e}")
                retry_count += 1
                if retry_count < max_retries:
                    self._handle_retry_wait(retry_count, max_retries)
                    continue
                return None

        LOGGER.error("Max retry attempts reached. Failed to send message to Kafka.")
        return None

    def start(self) -> None:
        """Start the Kafka service and keep running until shutdown."""
        while not self.shutdown_event.is_set():
            try:
                if not self.producer:
                    self.connect()

                # Keep running until shutdown or error
                while not self.shutdown_event.is_set():
                    self.shutdown_event.wait(1)

            except Exception as e:
                LOGGER.error(f"Error in Kafka service: {e}", exc_info=True)
                time.sleep(self.config.service_retry_interval)  # Wait before retry

        # Cleanup on shutdown
        self.stop()

    def stop(self) -> None:
        """Stop the Kafka service and cleanup resources."""
        try:
            if self.producer:
                self.producer.flush()  # Wait for any pending messages
                self.producer = None
                LOGGER.info("Kafka producer stopped successfully")
        except Exception as e:
            LOGGER.error(f"Error stopping Kafka producer: {e}")
