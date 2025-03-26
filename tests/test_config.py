"""Test configuration module."""

import pytest

from wazuh_dfn.config import Config, DFNConfig, KafkaConfig, LogConfig, MiscConfig, WazuhConfig
from wazuh_dfn.exceptions import ConfigValidationError


@pytest.fixture
def sample_config_yaml(tmp_path):
    """Create a sample configuration file."""
    config_content = """
dfn:
    dfn_id: "test-id"
    dfn_broker: "test:9092"
    dfn_ca: "ca.pem"
    dfn_cert: "cert.pem"
    dfn_key: "key.pem"
wazuh:
    json_alert_file: "/var/ossec/logs/alerts/alerts.json"
    unix_socket_path: "/var/ossec/queue/sockets/queue"
    max_event_size: 65535
    json_alert_prefix: '{"timestamp"'
    json_alert_suffix: "}"
    json_alert_file_poll_interval: 1.0
    max_retries: 5
    retry_interval: 5
kafka:
    timeout: 60
    retry_interval: 5
    connection_max_retries: 5
    send_max_retries: 5
    max_wait_time: 60
    service_retry_interval: 5
    admin_timeout: 10
log:
    console: true
    file_path: "/opt/wazuh-dfn/logs/wazuh-dfn.log"
    level: "INFO"
    interval: 600
misc:
    num_workers: 10
    own_network: null
"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)
    return str(config_file)


def test_config_from_yaml(sample_config_yaml):
    """Test configuration loading from YAML."""
    config = Config()  # Start with defaults
    config = Config.from_yaml(sample_config_yaml, config)  # Load YAML into existing config
    assert isinstance(config, Config)
    assert isinstance(config.dfn, DFNConfig)
    assert isinstance(config.wazuh, WazuhConfig)
    assert isinstance(config.kafka, KafkaConfig)
    assert isinstance(config.log, LogConfig)
    assert isinstance(config.misc, MiscConfig)


def test_config_validation_error(tmp_path):
    """Test configuration validation error."""
    # Create invalid config file
    config_content = """
dfn:
    dfn_id: ""  # Empty DFN ID
    dfn_broker: ""  # Empty broker
"""
    config_file = tmp_path / "invalid_config.yaml"
    config_file.write_text(config_content)

    config = Config()  # Start with defaults
    with pytest.raises(ConfigValidationError):
        Config.from_yaml(str(config_file), config)


def test_config_file_not_found():
    """Test configuration file not found error."""
    config = Config()  # Start with defaults
    with pytest.raises(FileNotFoundError):
        Config.from_yaml("nonexistent.yaml", config)


def test_config_invalid_yaml(tmp_path):
    """Test invalid YAML configuration."""
    config_content = """
dfn:
    dfn_id: "test-id"
    dfn_broker: test:9092  # Missing quotes
    invalid yaml content
"""
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(config_content)

    config = Config()  # Start with defaults
    with pytest.raises(ConfigValidationError):
        Config.from_yaml(str(config_file), config)


def test_config_get_method(sample_config_yaml):
    """Test configuration get method."""
    config = Config()  # Start with defaults
    config = Config.from_yaml(sample_config_yaml, config)  # Load YAML into existing config

    # Test valid keys
    assert config.get("dfn.dfn_id") == "test-id"
    assert config.get("wazuh.max_event_size") == "65535"
    assert config.get("kafka.timeout") == "60"
    assert config.get("log.level") == "INFO"
    assert config.get("misc.num_workers") == "10"

    # Test invalid keys with default
    assert config.get("invalid.key1", "default") == "default"
    
    # Test invalid keys without default - use a different key to avoid cache
    assert config.get("invalid.key2") == ""


def test_empty_config():
    """Test empty configuration."""
    config = Config()
    assert isinstance(config.dfn, DFNConfig)
    assert isinstance(config.wazuh, WazuhConfig)
    assert isinstance(config.kafka, KafkaConfig)
    assert isinstance(config.log, LogConfig)
    assert isinstance(config.misc, MiscConfig)


def test_config_from_env(monkeypatch):
    """Test configuration loading from environment variables."""
    # Set environment variables
    env_vars = {
        "DFN_CUSTOMER_ID": "env-test-id",
        "DFN_BROKER_ADDRESS": "env-broker:9092",
        "WAZUH_MAX_EVENT_SIZE": "32768",
        "KAFKA_TIMEOUT": "30",
        "LOG_LEVEL": "DEBUG",
        "MISC_NUM_WORKERS": "5",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Start with defaults
    config = Config()
    # Load from environment
    Config._load_from_env(config)

    # Check values are properly converted to their correct types
    assert config.dfn.dfn_id == "env-test-id"  # string
    assert config.dfn.dfn_broker == "env-broker:9092"  # string
    assert config.wazuh.max_event_size == 32768  # int
    assert config.kafka.timeout == 30  # int
    assert config.log.level == "DEBUG"  # string
    assert config.misc.num_workers == 5  # int


def test_config_from_cli():
    """Test configuration loading from CLI arguments."""

    class MockArgs:
        dfn_customer_id = "cli-test-id"
        dfn_broker_address = "cli-broker:9092"
        wazuh_max_event_size = 16384  # int
        kafka_timeout = 45  # int
        log_level = "WARNING"
        misc_num_workers = 3  # int

    # Start with defaults
    config = Config()
    # Load from CLI
    Config._load_from_cli(config, MockArgs())

    # Check values are properly converted to their correct types
    assert config.dfn.dfn_id == "cli-test-id"  # string
    assert config.dfn.dfn_broker == "cli-broker:9092"  # string
    assert config.wazuh.max_event_size == 16384  # int
    assert config.kafka.timeout == 45  # int
    assert config.log.level == "WARNING"  # string
    assert config.misc.num_workers == 3  # int


def test_kafka_producer_config():
    """Test Kafka producer configuration validation."""
    config = KafkaConfig()

    # Test default producer config
    assert config.producer_config["request.timeout.ms"] == 60000
    assert config.producer_config["enable.idempotence"] is True
    assert config.producer_config["acks"] == "all"

    # Test custom producer config
    custom_config = KafkaConfig()
    custom_config.producer_config["batch.size"] = 32768
    custom_config.producer_config["linger.ms"] = 2000

    assert custom_config.producer_config["batch.size"] == 32768
    assert custom_config.producer_config["linger.ms"] == 2000


def test_config_generate_sample(tmp_path):
    """Test sample configuration generation."""
    output_path = str(tmp_path / "sample_config.yaml")
    Config._generate_sample_config(output_path)

    # Verify file exists and contains expected content
    with open(output_path, "r") as f:
        content = f.read()
        assert "dfn:" in content
        assert "wazuh:" in content
        assert "kafka:" in content
        assert "log:" in content
        assert "misc:" in content


def test_config_validation_edge_cases(tmp_path):
    """Test configuration validation edge cases."""
    # Test invalid log level
    config_content = """
log:
    level: "INVALID_LEVEL"
"""
    config_file = tmp_path / "invalid_log.yaml"
    config_file.write_text(config_content)
    with pytest.raises(ConfigValidationError):
        Config.from_yaml(str(config_file))

    # Test invalid worker count
    config_content = """
misc:
    num_workers: -1
"""
    config_file = tmp_path / "invalid_workers.yaml"
    config_file.write_text(config_content)
    with pytest.raises(ConfigValidationError):
        Config.from_yaml(str(config_file))

    # Test invalid network CIDR
    config_content = """
misc:
    own_network: "invalid_cidr"
"""
    config_file = tmp_path / "invalid_network.yaml"
    config_file.write_text(config_content)
    with pytest.raises(ConfigValidationError):
        Config.from_yaml(str(config_file))


def test_config_priority_order(tmp_path, monkeypatch):
    """Test configuration loading priority: CLI args -> env vars -> YAML -> defaults."""
    # Create a YAML config with some values
    config_content = """
dfn:
    dfn_id: "yaml-id"
    dfn_broker: "yaml-broker:443"
wazuh:
    max_event_size: 32768
log:
    level: "WARNING"
"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)

    # Set environment variables (should override YAML)
    env_vars = {
        "DFN_CUSTOMER_ID": "env-id",  # Should override YAML
        "WAZUH_MAX_EVENT_SIZE": "16384",  # Should override YAML
        "LOG_LEVEL": "ERROR",  # Should override YAML
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Create CLI arguments (should override env vars)
    class MockArgs:
        dfn_customer_id = "cli-id"  # Should override env var
        dfn_broker_address = None  # Not set, should keep env var value
        wazuh_max_event_size = None  # Not set, should keep env var value
        log_level = "DEBUG"  # Should override env var

        def __init__(self):
            self.config = str(config_file)

    # Load config in correct order: defaults -> YAML -> env vars -> CLI args
    config = Config()  # Start with defaults
    config = Config.from_yaml(str(config_file), config)  # Load YAML into existing config
    Config._load_from_env(config)  # Load env vars
    Config._load_from_cli(config, MockArgs())  # Load CLI args

    # Verify defaults are used when not overridden
    assert config.kafka.timeout == 60  # Default value

    # Verify YAML values are used when not overridden by env or CLI
    assert config.dfn.dfn_broker == "yaml-broker:443"  # From YAML, not overridden

    # Verify env vars override YAML but not CLI
    assert config.wazuh.max_event_size == 16384  # From env var

    # Verify CLI args have highest priority
    assert config.dfn.dfn_id == "cli-id"  # CLI overrides both YAML and env
    assert config.log.level == "DEBUG"  # CLI overrides both YAML and env


def test_wazuh_config_defaults():
    """Test WazuhConfig default values."""
    config = WazuhConfig()
    assert config.json_alert_file == "/var/ossec/logs/alerts/alerts.json"
    assert config.json_alert_file_poll_interval == pytest.approx(1.0)
    assert config.json_alert_prefix == '{"timestamp"'
    assert config.json_alert_suffix == "}"
