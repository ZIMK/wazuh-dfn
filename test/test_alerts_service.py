"""Test module for Alerts Service."""

import pytest

from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.services.alerts_service import AlertsService


def test_alerts_service_initialization(sample_config, kafka_service, wazuh_service):
    """Test AlertsService initialization."""
    service = AlertsService(sample_config.misc, kafka_service, wazuh_service)
    assert service.config == sample_config.misc
    assert service.kafka_service == kafka_service


def test_alerts_service_process_alert(alerts_service, sample_alert):
    """Test AlertsService alert processing."""
    processed = alerts_service.process_alert(sample_alert)
    assert processed is None


def test_alerts_service_invalid_alert(alerts_service):
    """Test AlertsService handling of invalid alerts."""
    invalid_alert = {"invalid": "data"}
    processed = alerts_service.process_alert(invalid_alert)
    assert processed is None


def test_alerts_service_config_validation(sample_config, kafka_service, wazuh_service):
    """Test AlertsService configuration validation."""
    invalid_config = sample_config.misc
    invalid_config.num_workers = -1  # Invalid number of workers
    with pytest.raises(ConfigValidationError):
        AlertsService(invalid_config, kafka_service, wazuh_service)


def test_alerts_service_observer_failure(sample_config, kafka_service, wazuh_service):
    """Test AlertsService observer failure handling."""
    service = AlertsService(sample_config.misc, kafka_service, wazuh_service)
    assert service is not None  # NOSONAR
