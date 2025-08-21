"""Tests for wazuh_dfn.exceptions module."""

import pytest

from wazuh_dfn.exceptions import (
    AlertProcessingError,
    ConfigValidationError,
    KafkaError,
    ServiceError,
    WazuhError,
)


def test_config_validation_error():
    """Test ConfigValidationError exception."""
    message = "Invalid configuration parameter"
    error = ConfigValidationError(message)

    assert isinstance(error, Exception)
    assert str(error) == message
    assert error.args == (message,)


def test_alert_processing_error():
    """Test AlertProcessingError exception."""
    message = "Failed to process alert"
    error = AlertProcessingError(message)

    assert isinstance(error, Exception)
    assert str(error) == message
    assert error.args == (message,)


def test_service_error():
    """Test ServiceError exception."""
    message = "Service operation failed"
    error = ServiceError(message)

    assert isinstance(error, Exception)
    assert str(error) == message
    assert error.args == (message,)


def test_kafka_error():
    """Test KafkaError exception."""
    message = "Kafka connection failed"
    error = KafkaError(message)

    assert isinstance(error, Exception)
    assert str(error) == message
    assert error.args == (message,)


def test_wazuh_error():
    """Test WazuhError exception."""
    message = "Wazuh API call failed"
    error = WazuhError(message)

    assert isinstance(error, Exception)
    assert str(error) == message
    assert error.args == (message,)


def test_exceptions_inheritance():
    """Test that all custom exceptions inherit from Exception."""
    exceptions = [
        ConfigValidationError,
        AlertProcessingError,
        ServiceError,
        KafkaError,
        WazuhError,
    ]

    for exc_class in exceptions:
        assert issubclass(exc_class, Exception)


def test_exceptions_with_args():
    """Test exceptions with multiple arguments."""
    message = "Primary error message"
    detail = "Additional error details"

    error = ConfigValidationError(message, detail)
    assert error.args == (message, detail)
    # When there are multiple args, str() returns the tuple representation
    assert str(error) == f"('{message}', '{detail}')"


def test_exceptions_without_args():
    """Test exceptions can be raised without arguments."""
    for exc_class in [ConfigValidationError, AlertProcessingError, ServiceError, KafkaError, WazuhError]:
        error = exc_class()
        assert isinstance(error, Exception)
        assert error.args == ()


@pytest.mark.parametrize(
    "exception_class,message",
    [
        (ConfigValidationError, "Config validation failed"),
        (AlertProcessingError, "Alert processing failed"),
        (ServiceError, "Service failed"),
        (KafkaError, "Kafka failed"),
        (WazuhError, "Wazuh failed"),
    ],
)
def test_exception_raising(exception_class, message):
    """Test that exceptions can be properly raised and caught."""
    with pytest.raises(exception_class) as exc_info:
        raise exception_class(message)

    assert str(exc_info.value) == message
    assert isinstance(exc_info.value, exception_class)
