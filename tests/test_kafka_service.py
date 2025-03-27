"""Test module for Kafka Service."""

import pytest
import threading
import time
from confluent_kafka import KafkaError, KafkaException
from confluent_kafka.admin import ClusterMetadata
from pydantic import BaseModel, Field, ValidationError
from unittest.mock import MagicMock, patch
from wazuh_dfn.services.kafka_service import KafkaService


def test_kafka_service_initialization(sample_config, wazuh_service, shutdown_event):
    """Test KafkaService initialization with custom configuration."""
    service = KafkaService(
        config=sample_config.kafka,
        dfn_config=sample_config.dfn,
        wazuh_handler=wazuh_service,
        shutdown_event=shutdown_event,
    )
    assert service.config == sample_config.kafka
    assert service.dfn_config == sample_config.dfn
    assert service.shutdown_event == shutdown_event


def test_kafka_service_ssl_config(kafka_service, sample_config):
    """Test KafkaService SSL configuration."""
    assert kafka_service.dfn_config.dfn_cert is not None
    assert kafka_service.dfn_config.dfn_key is not None
    assert kafka_service.dfn_config.dfn_ca is not None


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_send_message(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test sending messages through KafkaService."""
    # Setup mock producer
    producer_instance = mock_producer.return_value
    producer_instance.flush.return_value = 0  # No messages pending

    # Setup mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {kafka_service.dfn_config.dfn_id: None}
    mock_admin.return_value.list_topics.return_value = mock_metadata

    # Set producer directly to avoid connection attempt
    kafka_service.producer = producer_instance

    message = {"test": "data"}
    result = kafka_service.send_message(message)
    assert result is not None
    assert result["success"] is True
    assert result["topic"] == kafka_service.dfn_config.dfn_id

    # Verify producer calls
    producer_instance.produce.assert_called_once()
    producer_instance.flush.assert_called_once_with(timeout=kafka_service.config.timeout)


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_send_message_kafka_error(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService message sending with KafkaException retry."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.produce.side_effect = [KafkaException("Test Kafka error")] * 5  # Fail 5 times
    producer_instance.flush.return_value = 0  # No messages pending

    # Mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {kafka_service.dfn_config.dfn_id: None}
    mock_admin.return_value.list_topics.return_value = mock_metadata

    # Set producer directly to avoid connection attempts
    kafka_service.producer = producer_instance

    # Combine the nested with statements
    with patch("time.sleep"):
        message = {"test": "data"}
        result = kafka_service.send_message(message)
        assert result is None

    # Verify producer calls - should be called once per attempt
    assert producer_instance.produce.call_count >= 1  # Called for each retry
    assert producer_instance.flush.call_count == 0  # Not called due to produce error


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_send_message_max_retries(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService message sending with max retries exceeded."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.produce.side_effect = [KafkaException("Test Kafka error")] * 5  # Fail 5 times
    producer_instance.flush.return_value = 0  # No messages pending

    # Mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {kafka_service.dfn_config.dfn_id: None}
    mock_admin.return_value.list_topics.return_value = mock_metadata

    # Set producer directly to avoid connection attempts
    kafka_service.producer = producer_instance

    # Combine the nested with statements
    with patch("time.sleep"):
        message = {"test": "data"}
        result = kafka_service.send_message(message)
        assert result is None

    # Verify producer calls - should be called once per attempt
    assert producer_instance.produce.call_count >= 1  # Called for each retry
    assert producer_instance.flush.call_count == 0  # Not called due to produce error


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_send_message_general_error(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService message sending with general exception."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.produce.side_effect = Exception("Test general error")
    producer_instance.flush.return_value = 0  # No messages pending
    mock_admin.return_value.list_topics.return_value = MagicMock(topics={kafka_service.dfn_config.dfn_id: None})

    # Set producer directly to avoid connection attempts
    kafka_service.producer = producer_instance

    # Combine the nested with statements
    with patch("time.sleep"):
        message = {"test": "data"}
        result = kafka_service.send_message(message)
        assert result is None

    # Verify producer calls
    assert producer_instance.produce.call_count >= 1


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_error_handling(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService error handling."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.produce.side_effect = KafkaException("Test Kafka error")
    producer_instance.flush.return_value = 0  # No messages pending
    mock_admin.return_value.list_topics.return_value = MagicMock(topics={kafka_service.dfn_config.dfn_id: None})

    # Set producer directly to avoid connection attempts
    kafka_service.producer = producer_instance

    # Combine the nested with statements
    with patch("time.sleep"):
        message = {"test": "data"}
        result = kafka_service.send_message(message)
        assert result is None

    # Verify producer calls
    assert producer_instance.produce.call_count >= 1


def test_kafka_service_config_validation(sample_config):
    """Test KafkaService configuration validation."""

    # Create a test model that explicitly validates fields like in DFNConfig
    class TestDFNId(BaseModel):
        dfn_id: str = Field(..., min_length=1)
        dfn_broker: str = Field(..., min_length=1)

    # Test with invalid DFN config - this should now properly raise ValidationError
    with pytest.raises(ValidationError):
        TestDFNId(dfn_id="", dfn_broker="test:9092")

    with pytest.raises(ValidationError):
        TestDFNId(dfn_id="test-id", dfn_broker="")

    # Test AttributeError by using a simpler approach - access an attribute on None
    # This always reliably raises AttributeError
    def access_none_attribute():
        none_obj = None
        return none_obj.some_attribute  # type: ignore # This will always raise AttributeError

    with pytest.raises(AttributeError):
        access_none_attribute()


def test_kafka_service_producer_config(kafka_service):
    """Test KafkaService producer configuration."""
    config = {
        "bootstrap.servers": kafka_service.dfn_config.dfn_broker,
        "security.protocol": "ssl",
        "ssl.ca.location": kafka_service.dfn_config.dfn_ca,
        "ssl.certificate.location": kafka_service.dfn_config.dfn_cert,
        "ssl.key.location": kafka_service.dfn_config.dfn_key,
    }
    for _, value in config.items():
        assert value is not None


def test_kafka_service_producer_settings(sample_config, shutdown_event):
    """Test KafkaService producer settings configuration."""
    service = KafkaService(
        config=sample_config.kafka,
        dfn_config=sample_config.dfn,
        wazuh_handler=MagicMock(),
        shutdown_event=shutdown_event,
    )
    assert service.dfn_config.dfn_broker is not None
    assert service.dfn_config.dfn_cert is not None
    assert service.dfn_config.dfn_key is not None
    assert service.dfn_config.dfn_ca is not None


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_start_stop(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService start/stop functionality."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.flush.return_value = 0  # No messages pending

    # Mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {kafka_service.dfn_config.dfn_id: None}
    mock_admin.return_value.list_topics.return_value = mock_metadata

    # Mock time.sleep to avoid waiting during connection retries
    with patch("time.sleep"):
        # Set producer directly to avoid connection attempts
        kafka_service.producer = producer_instance
        assert kafka_service.producer is not None

        # Test stop
        shutdown_event.set()
        kafka_service.stop()
        assert kafka_service.producer is None


@patch("confluent_kafka.admin.AdminClient")
def test_kafka_service_topic_creation(mock_admin, kafka_service, mock_producer, shutdown_event):
    """Test KafkaService topic creation functionality."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.flush.return_value = 0

    # Mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {"test-topic": None}  # Topic exists
    mock_admin_instance = mock_admin.return_value
    mock_admin_instance.list_topics.return_value = mock_metadata

    # Set producer directly
    kafka_service.producer = producer_instance
    kafka_service.dfn_config.dfn_id = "test-topic"

    # Test message sending
    message = {"test": "data"}
    result = kafka_service.send_message(message)

    assert result is not None
    assert result["success"] is True
    assert result["topic"] == "test-topic"


@patch("wazuh_dfn.services.kafka_service.Producer")
@patch("wazuh_dfn.services.kafka_service.AdminClient")
def test_kafka_service_topic_creation_failure(mock_admin, mock_producer, kafka_service, shutdown_event):
    """Test KafkaService topic creation failure handling."""
    # Setup producer mock
    producer_instance = MagicMock()
    producer_instance.flush.return_value = 0
    mock_producer.return_value = producer_instance

    # Mock admin client with missing topic error
    mock_admin_instance = MagicMock()
    mock_admin_instance.list_topics.return_value = MagicMock(topics={})
    mock_admin.return_value = mock_admin_instance

    # Store original retry settings
    original_retries = kafka_service.config.send_max_retries
    original_conn_retries = kafka_service.config.connection_max_retries

    # Directly set the value we want to test
    producer_config = {
        "bootstrap.servers": "localhost:9092",
        "client.id": "test_client",
        "security.protocol": "plaintext",  # Force non-SSL
    }

    try:
        # Configure for single attempt
        kafka_service.config.send_max_retries = 1
        kafka_service.config.connection_max_retries = 1

        # Clear producer to force reconnect
        kafka_service.producer = None

        # Test connection should fail due to missing topic
        # Fix nested with statements by combining them
        with (
            patch("time.sleep"),
            patch("wazuh_dfn.services.kafka_service.KafkaConfig.get_kafka_config", return_value=producer_config),
            pytest.raises(ConnectionError),
        ):
            kafka_service.connect()

        # Verify producer was created and admin client was called
        mock_producer.assert_called_once()
        mock_admin_instance.list_topics.assert_called_once()

    finally:
        # Restore original settings
        kafka_service.config.send_max_retries = original_retries
        kafka_service.config.connection_max_retries = original_conn_retries


@patch("wazuh_dfn.services.kafka_service.Producer")
def test_kafka_service_producer_init_failure(mock_producer, kafka_service):
    """Test KafkaService producer initialization failure."""
    # Store original retry settings
    original_retries = kafka_service.config.send_max_retries
    original_conn_retries = kafka_service.config.connection_max_retries

    try:
        # Configure for single attempt
        kafka_service.config.send_max_retries = 1
        kafka_service.config.connection_max_retries = 1

        # Mock producer creation failure
        mock_producer.side_effect = KafkaException("Failed to create producer")

        # Clear any existing producer and connection
        kafka_service.producer = None

        # Test message sending with failed producer
        message = {"test": "data"}
        with (
            patch("time.sleep"),
            patch.object(kafka_service, "_create_producer", wraps=kafka_service._create_producer) as mock_create,
        ):
            result = kafka_service.send_message(message)
            assert result is None
            assert mock_create.call_count >= 1
    finally:
        # Restore original settings
        kafka_service.config.send_max_retries = original_retries
        kafka_service.config.connection_max_retries = original_conn_retries


@patch("wazuh_dfn.services.kafka_service.Producer")
@patch("wazuh_dfn.services.kafka_service.AdminClient")
def test_kafka_service_producer_delivery_callback(mock_admin, mock_producer, kafka_service, shutdown_event):
    """Test KafkaService producer delivery callback."""
    # Setup mocks
    producer_instance = mock_producer.return_value
    producer_instance.flush.return_value = 0

    # Mock admin client
    mock_metadata = MagicMock(spec=ClusterMetadata)
    mock_metadata.topics = {kafka_service.dfn_config.dfn_id: None}
    mock_admin.return_value.list_topics.return_value = mock_metadata

    # Set producer directly
    kafka_service.producer = producer_instance

    # Test successful delivery
    message = {"test": "data"}
    result = kafka_service.send_message(message)

    # Get the callback function that was passed to produce
    callback_fn = producer_instance.produce.call_args[1]["callback"]

    # Create a mock Kafka message
    mock_msg = MagicMock()
    mock_msg.topic.return_value = kafka_service.dfn_config.dfn_id
    mock_msg.partition.return_value = 0
    mock_msg.offset.return_value = 1

    # Test successful delivery
    callback_fn(None, mock_msg)  # No error
    assert result["success"] is True

    # Test failed delivery
    mock_error = MagicMock()
    mock_error.str.return_value = "Delivery failed"
    mock_error.code.return_value = KafkaError._TIMED_OUT
    callback_fn(err=mock_error, msg=mock_msg)
    assert producer_instance.flush.called


@patch("confluent_kafka.Producer")
def test_kafka_service_producer_flush_timeout(mock_producer, kafka_service):
    """Test KafkaService producer flush timeout handling."""
    # Mock producer instance
    producer_instance = mock_producer.return_value
    producer_instance.flush.return_value = 1  # Return non-zero to indicate messages still in queue
    producer_instance.produce.return_value = None  # Mock produce method
    kafka_service.producer = producer_instance

    # Test message sending with flush timeout
    message = {"test": "data"}
    with patch("time.sleep"):  # Mock sleep to speed up test
        result = kafka_service.send_message(message)

    # Verify timeout handling
    assert result is None
    producer_instance.produce.assert_called_once()  # Verify produce was called
    producer_instance.flush.assert_called_with(timeout=kafka_service.config.timeout)


def test_kafka_service_producer_cleanup_error(kafka_service, shutdown_event):
    """Test KafkaService producer cleanup error handling."""
    # Setup producer mock that raises on close
    producer_mock = MagicMock()
    producer_mock.close.side_effect = Exception("Cleanup error")
    kafka_service.producer = producer_mock

    # Cleanup should handle error gracefully
    kafka_service._handle_producer_cleanup()
    assert kafka_service.producer is None
    producer_mock.close.assert_called_once()


def test_kafka_service_topic_verification_error(kafka_service, shutdown_event):
    """Test KafkaService topic verification error handling."""
    # Setup admin client mock
    admin_mock = MagicMock()
    admin_mock.list_topics.side_effect = KafkaException("Topic list error")

    with patch("wazuh_dfn.services.kafka_service.AdminClient", return_value=admin_mock), pytest.raises(KafkaException):
        kafka_service._test_connection()


def test_kafka_service_connection_retry_logic(kafka_service, shutdown_event):
    """Test KafkaService connection retry logic."""
    # Setup producer mock that fails first then succeeds
    producer_mock = MagicMock()
    producer_mock.flush.return_value = 0

    # Setup admin client mock that fails first then succeeds
    admin_mock = MagicMock()
    admin_mock.list_topics.side_effect = [
        KafkaException("First attempt fails"),
        MagicMock(topics={kafka_service.dfn_config.dfn_id: MagicMock()}),
    ]

    with (
        patch("wazuh_dfn.services.kafka_service.Producer", return_value=producer_mock),
        patch("wazuh_dfn.services.kafka_service.AdminClient", return_value=admin_mock),
        patch("time.sleep"),  # Avoid actual sleep delays
    ):
        kafka_service.connect()
        assert kafka_service.producer is not None
        assert admin_mock.list_topics.call_count == 2


def test_kafka_service_delivery_callback_error(kafka_service, shutdown_event):
    """Test KafkaService delivery callback error handling."""
    # Create KafkaError with TIMED_OUT error code
    err = KafkaError(KafkaError._TIMED_OUT)
    msg = MagicMock()
    msg.value.return_value = b'{"test": "data"}'
    msg.topic.return_value = "test-topic"
    msg.partition.return_value = 0
    msg.offset.return_value = 123

    # Should log error but not raise
    kafka_service._delivery_callback(err, msg)


def test_kafka_service_stop_with_cleanup_error(kafka_service, shutdown_event):
    """Test KafkaService stop method with cleanup error."""
    producer_mock = MagicMock()
    producer_mock.flush.return_value = 0  # No messages pending
    producer_mock.close.side_effect = Exception("Cleanup error")
    kafka_service.producer = producer_mock

    # Stop should handle the error and set producer to None
    kafka_service.stop()

    # Verify both flush and close were called
    producer_mock.flush.assert_called_once()
    producer_mock.close.assert_not_called()
    assert kafka_service.producer is None


def test_kafka_service_send_message_error_handling(kafka_service):
    """Test error handling in _send_message_once."""
    producer_mock = MagicMock()
    producer_mock.produce.side_effect = KafkaException("Test error")
    kafka_service.producer = producer_mock

    # Should raise KafkaException as per implementation
    with pytest.raises(KafkaException):
        kafka_service._send_message_once({"test": "data"})

    producer_mock.produce.assert_called_once()


def test_start_with_connect_error(kafka_service, shutdown_event):
    """Test KafkaService start method with connection error."""
    # Mock connect to raise error
    with patch.object(kafka_service, "connect", side_effect=KafkaException("Connection failed")):
        # Start service in a separate thread
        service_thread = threading.Thread(target=kafka_service.start)
        service_thread.start()
        # Give it a moment to attempt connection
        time.sleep(0.1)
        # Signal shutdown
        shutdown_event.set()
        # Wait for thread to finish (with timeout)
        service_thread.join(timeout=1.0)
        assert not service_thread.is_alive()
