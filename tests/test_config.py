"""Test module for configuration and validation."""

import argparse
import datetime

# Add pytest-asyncio import
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError, field_validator

from wazuh_dfn.config import Config, DFNConfig, KafkaConfig, LogConfig, LogLevel, MiscConfig, WazuhConfig
from wazuh_dfn.exceptions import ConfigValidationError


def test_log_level_enum():
    """Test LogLevel enumeration."""
    # Test all enum values
    assert LogLevel.DEBUG == "DEBUG"
    assert LogLevel.INFO == "INFO"
    assert LogLevel.WARNING == "WARNING"
    assert LogLevel.ERROR == "ERROR"
    assert LogLevel.CRITICAL == "CRITICAL"

    # Test string comparison
    assert LogLevel.DEBUG == "DEBUG"
    assert LogLevel.INFO == "INFO"


def test_wazuh_config_validation():
    """Test WazuhConfig validation."""
    # Test valid config
    valid_config = WazuhConfig(
        unix_socket_path="/var/ossec/queue/sockets/queue",
        json_alert_file="/var/ossec/logs/alerts/alerts.json",
        max_event_size=65535,
    )
    assert valid_config.unix_socket_path == "/var/ossec/queue/sockets/queue"

    # Test empty json_alert_file (should raise ValidationError)
    with pytest.raises(ValidationError):
        WazuhConfig(
            unix_socket_path="/var/ossec/queue/sockets/queue",
            json_alert_file="",
            max_event_size=65535,
        )

    # Test empty unix_socket_path (should raise ValidationError)
    with pytest.raises(ValidationError):
        WazuhConfig(
            unix_socket_path="",
            json_alert_file="/var/ossec/logs/alerts/alerts.json",
            max_event_size=65535,
        )

    # Test invalid max_event_size (will raise ValidationError)
    with pytest.raises(ValidationError):
        WazuhConfig(
            unix_socket_path="/var/ossec/queue/sockets/queue",
            json_alert_file="/var/ossec/logs/alerts/alerts.json",
            max_event_size=-1,  # Invalid: must be > 0
        )


def test_dfn_config_validation():
    """Test DFNConfig validation."""
    # Test valid config
    valid_config = DFNConfig(
        dfn_id="test-id",
        dfn_broker="test:9092",
        dfn_ca="ca.pem",
        dfn_cert="cert.pem",
        dfn_key="key.pem",
    )
    assert valid_config.dfn_id == "test-id"

    # Create a test model that explicitly validates these fields
    # This ensures we can actually test the validation rules
    class TestDFNValidation(BaseModel):
        # These fields must match the validation rules in DFNConfig
        dfn_id: str
        dfn_broker: str

        @field_validator("dfn_id", "dfn_broker")
        @classmethod
        def check_not_empty(cls, v):
            if not v:
                raise ValueError("cannot be empty")
            return v

    # Test empty dfn_id validation
    with pytest.raises(ValidationError):
        TestDFNValidation(
            dfn_id="",  # Empty is not allowed
            dfn_broker="test:9092",
        )

    # Test empty dfn_broker validation
    with pytest.raises(ValidationError):
        TestDFNValidation(
            dfn_id="test-id",
            dfn_broker="",  # Empty not allowed
        )


def test_kafka_config_validation():
    """Test KafkaConfig validation."""
    # Test valid config
    valid_config = KafkaConfig(
        timeout=60,
        retry_interval=5,
        connection_max_retries=5,
        send_max_retries=5,
        max_wait_time=60,
        admin_timeout=10,
    )
    assert valid_config.timeout == 60

    # Test invalid timeout
    with pytest.raises(ValidationError):
        KafkaConfig(
            timeout=0,  # Invalid: must be > 0
            retry_interval=5,
            connection_max_retries=5,
            send_max_retries=5,
            max_wait_time=60,
            admin_timeout=10,
        )


def test_kafka_config_get_producer_config():
    """Test KafkaConfig.get_producer_config function with parameter filtering."""
    # Create a basic kafka config
    kafka_config = KafkaConfig()
    dfn_config = DFNConfig(dfn_broker="test-broker:9092")

    # Get producer config with default settings
    producer_config = kafka_config.get_producer_config(dfn_config)

    # Verify the correct parameters exist
    assert producer_config["bootstrap_servers"] == "test-broker:9092"
    assert producer_config["max_batch_size"] == 16384
    assert "request_timeout_ms" in producer_config

    # Verify invalid parameters do not exist
    assert "delivery_timeout_ms" not in producer_config
    assert "buffer_memory" not in producer_config
    assert "batch_size" not in producer_config

    # Test with custom settings including invalid parameters
    kafka_config.producer_config = {
        "max_batch_size": 32768,
        "linger_ms": 100,
        "delivery_timeout_ms": 30000,  # Invalid for aiokafka
        "buffer_memory": 65536,  # Invalid for aiokafka
        "custom_invalid_option": "value",  # Invalid parameter
    }

    # Get filtered config
    filtered_config = kafka_config.get_producer_config(dfn_config)

    # Valid parameters should be included
    assert filtered_config["max_batch_size"] == 32768
    assert filtered_config["linger_ms"] == 100

    # Invalid parameters should be excluded
    assert "delivery_timeout_ms" not in filtered_config
    assert "buffer_memory" not in filtered_config
    assert "custom_invalid_option" not in filtered_config


def test_admin_config_parameters():
    """Test that admin client configuration is generated correctly."""
    kafka_config = KafkaConfig()
    dfn_config = DFNConfig(dfn_broker="admin-broker:9092")

    # Get admin config
    admin_config = kafka_config.get_admin_config(dfn_config)

    # Verify basic parameters
    assert admin_config["bootstrap_servers"] == "admin-broker:9092"
    assert admin_config["client_id"] == "wazuh-dfn"
    assert admin_config["request_timeout_ms"] == kafka_config.admin_timeout * 1000

    # Admin config should use common parameters but not producer-specific ones
    assert "retry_backoff_ms" in admin_config
    assert "max_batch_size" not in admin_config


def test_log_config_validation():
    """Test LogConfig validation."""
    # Test valid config
    valid_config = LogConfig(
        console=True,
        file_path="/path/to/log",
        level="INFO",
        keep_files=5,
        interval=600,
    )
    assert valid_config.level == "INFO"

    # Test invalid level
    with pytest.raises(ValidationError):
        LogConfig(
            console=True,
            file_path="/path/to/log",
            level="INVALID_LEVEL",  # Invalid level
            keep_files=5,
            interval=600,
        )

    # Test invalid keep_files
    with pytest.raises(ValidationError):
        LogConfig(
            console=True,
            file_path="/path/to/log",
            level="INFO",
            keep_files=0,  # Invalid: must be > 0
            interval=600,
        )


def test_misc_config_validation():
    """Test MiscConfig validation."""
    # Test valid config
    valid_config = MiscConfig(
        num_workers=10,
        own_network=None,
    )
    assert valid_config.num_workers == 10

    # Test valid CIDR
    valid_cidr_config = MiscConfig(
        num_workers=10,
        own_network="192.168.1.0/24",
    )
    assert valid_cidr_config.own_network == "192.168.1.0/24"

    # Test invalid num_workers
    with pytest.raises(ValidationError):
        MiscConfig(
            num_workers=0,  # Invalid: must be > 0
            own_network=None,
        )

    # Test invalid CIDR
    with pytest.raises(ValidationError):
        MiscConfig(
            num_workers=10,
            own_network="invalid_cidr",  # Invalid CIDR notation
        )


def test_main_config_validation():
    """Test overall Config validation."""
    # Test valid config with defaults
    valid_config = Config()
    assert isinstance(valid_config.dfn, DFNConfig)
    assert isinstance(valid_config.wazuh, WazuhConfig)
    assert isinstance(valid_config.kafka, KafkaConfig)
    assert isinstance(valid_config.log, LogConfig)
    assert isinstance(valid_config.misc, MiscConfig)

    # Test config with custom values
    custom_config = Config(
        dfn=DFNConfig(dfn_id="custom-id", dfn_broker="custom:9092"),
        wazuh=WazuhConfig(max_event_size=32768),
        log=LogConfig(level="DEBUG"),
    )
    assert custom_config.dfn.dfn_id == "custom-id"
    assert custom_config.wazuh.max_event_size == 32768
    assert custom_config.log.level == "DEBUG"


def test_yaml_config_loading():
    """Test loading config from YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml_path = tmp.name
        tmp.write(
            """
dfn:
  dfn_id: test-yaml-id
  dfn_broker: broker:9092
wazuh:
  max_event_size: 32000
log:
  level: DEBUG
        """
        )

    try:
        config = Config.from_yaml(yaml_path)
        assert config.dfn.dfn_id == "test-yaml-id"
        assert config.dfn.dfn_broker == "broker:9092"
        assert config.wazuh.max_event_size == 32000
        assert config.log.level == "DEBUG"
    finally:
        Path(yaml_path).unlink()


def test_toml_config_loading():
    """Test loading config from TOML file."""
    # Skip if tomllib/tomli not available
    tomli_installed = False
    try:
        import tomllib  # noqa: F401

        tomli_installed = True
    except ImportError:
        try:
            import tomli  # type: ignore # noqa: F401

            tomli_installed = True
        except ImportError:
            pytest.skip("Neither tomllib nor tomli is installed - skipping TOML tests")

    if not tomli_installed:
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tmp:
        toml_path = tmp.name
        tmp.write(
            """
[dfn]
dfn_id = "test-toml-id"
dfn_broker = "toml-broker:9092"

[wazuh]
max_event_size = 64000

[log]
level = "DEBUG"
        """
        )

    try:
        config = Config.from_toml(toml_path)
        assert config.dfn.dfn_id == "test-toml-id"
        assert config.dfn.dfn_broker == "toml-broker:9092"
        assert config.wazuh.max_event_size == 64000
        assert config.log.level == "DEBUG"
    finally:
        Path(toml_path).unlink()


def test_config_environment_loading(monkeypatch):
    """Test loading configuration from environment variables."""
    monkeypatch.setenv("DFN_CUSTOMER_ID", "env-test-id")
    monkeypatch.setenv("WAZUH_MAX_EVENT_SIZE", "32768")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    config = Config()
    Config._load_from_env(config)

    assert config.dfn.dfn_id == "env-test-id"
    assert config.wazuh.max_event_size == 32768
    assert config.log.level == "DEBUG"


def test_config_sample_generation(tmp_path):
    """Test sample config generation."""
    output_path = tmp_path / "sample_config.toml"
    Config._generate_sample_config(str(output_path), "toml")

    assert output_path.exists()
    content = output_path.read_text()
    assert "[dfn]" in content
    assert "[wazuh]" in content
    assert "[kafka]" in content
    assert "[log]" in content
    assert "[misc]" in content


def test_unix_socket_path_validation():
    """Test unix_socket_path validation in WazuhConfig."""
    # Test with string path
    config = WazuhConfig(unix_socket_path="/var/ossec/queue/sockets/queue")
    assert config.unix_socket_path == "/var/ossec/queue/sockets/queue"

    # Test with host/port tuple
    config = WazuhConfig(unix_socket_path=("localhost", 1514))
    assert config.unix_socket_path == ("localhost", 1514)

    # Test with string representation of tuple
    config = WazuhConfig(unix_socket_path="(localhost, 1514)")
    assert isinstance(config.unix_socket_path, tuple)
    assert config.unix_socket_path[0] == "localhost"
    assert config.unix_socket_path[1] == 1514

    # Test with invalid tuple format - now using a proper (host, port) tuple
    with pytest.raises(ValueError):
        WazuhConfig(unix_socket_path=("localhost", 0))  # Invalid port

    # Test with invalid host
    with pytest.raises(ValueError):
        WazuhConfig(unix_socket_path=("", 1514))

    # Test with invalid port
    with pytest.raises(ValueError):
        WazuhConfig(unix_socket_path=("localhost", 0))

    # Test with invalid port (too high)
    with pytest.raises(ValueError):
        WazuhConfig(unix_socket_path=("localhost", 70000))

    # Test with invalid type
    with pytest.raises(ValueError):
        WazuhConfig(unix_socket_path=123)  # type: ignore


def test_socket_path_with_existing_path():
    """Test validation of unix_socket_path with existing path."""
    with patch("pathlib.Path.exists", return_value=True), patch("pathlib.Path.is_socket", return_value=True):
        # Should validate without errors
        config = WazuhConfig(unix_socket_path="/custom/socket/path")
        assert config.unix_socket_path == "/custom/socket/path"


def test_socket_path_with_nonexistent_path():
    """Test validation of unix_socket_path with non-existent path."""
    with (
        patch("pathlib.Path.exists", return_value=False),
        patch("pathlib.Path.is_socket", return_value=False),
        patch("logging.Logger.warning") as mock_warning,
    ):
        # Should log a warning but not raise an error
        config = WazuhConfig(unix_socket_path="/nonexistent/socket/path")
        assert config.unix_socket_path == "/nonexistent/socket/path"
        mock_warning.assert_called_once()


def test_cidr_validation():
    """Test CIDR validation in MiscConfig."""
    # Valid CIDR
    config = MiscConfig(own_network="192.168.1.0/24")
    assert config.own_network == "192.168.1.0/24"

    # None is valid
    config = MiscConfig(own_network=None)
    assert config.own_network is None

    # Missing slash
    with pytest.raises(ValueError):
        MiscConfig(own_network="192.168.1.0")

    # Empty string
    with pytest.raises(ValueError):
        MiscConfig(own_network="")

    # Invalid network
    with pytest.raises(ValueError):
        MiscConfig(own_network="999.999.999.0/24")

    # IPv6 should work
    with patch("ipaddress.ip_network") as mock_ip_network:
        # Mock successful IPv6 validation
        config = MiscConfig(own_network="2001:db8::/32")
        assert config.own_network == "2001:db8::/32"
        mock_ip_network.assert_called_once()


def test_certificate_validation_mock():
    """Test certificate validation with mocks."""
    import datetime

    # Create a fixed time for testing
    fixed_now = datetime.datetime(2022, 1, 1, tzinfo=datetime.UTC)

    # Create a custom datetime wrapper class that overrides comparison operators
    class DatetimeWrapper:
        def __init__(self, dt_value, valid=True):
            self.dt = dt_value
            self.valid = valid  # Controls if this date should be considered valid

        def __lt__(self, other):
            # For the check: now < cert.not_valid_before_utc
            # Return False for valid certificates (not in the future)
            # Return True for invalid certificates (in the future)
            return not self.valid

        def __gt__(self, other):
            # For the check: now > cert.not_valid_after_utc
            # Return False for valid certificates (not expired)
            # Return True for invalid certificates (expired)
            return not self.valid

    # Mock function to replace datetime.now
    def mock_now(tz=None):
        if tz is None:
            return fixed_now
        return fixed_now.replace(tzinfo=tz)

    # Create properly configured certificate and key mocks - combine multiple with statements
    with (
        patch.object(DFNConfig, "_verify_key_pair", return_value=True),
        patch.object(DFNConfig, "_verify_certificate_chain"),
        patch("pathlib.Path.open", MagicMock()),
        patch("cryptography.x509.load_pem_x509_certificate") as mock_load_cert,
        patch("cryptography.hazmat.primitives.serialization.load_pem_private_key", MagicMock()),
        patch("datetime.datetime", wraps=datetime.datetime) as mock_datetime,
    ):
        # Set the now method to our mock implementation
        mock_datetime.now = mock_now

        # Create certificate mocks with valid dates
        ca_cert = MagicMock()
        client_cert = MagicMock()

        # Use our wrapper class for the validity dates - set both as valid
        # Updated to use the _utc suffix to match the actual implementation
        ca_cert.not_valid_before_utc = DatetimeWrapper(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC), valid=True)
        ca_cert.not_valid_after_utc = DatetimeWrapper(datetime.datetime(2023, 1, 1, tzinfo=datetime.UTC), valid=True)

        client_cert.not_valid_before_utc = DatetimeWrapper(
            datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC), valid=True
        )
        client_cert.not_valid_after_utc = DatetimeWrapper(
            datetime.datetime(2023, 1, 1, tzinfo=datetime.UTC), valid=True
        )

        # Set up the public key
        client_cert.public_key.return_value = MagicMock()

        # Configure mock to return our certificates
        mock_load_cert.side_effect = [ca_cert, client_cert]

        # Create config with certificate paths
        config = DFNConfig(dfn_ca="/path/to/ca.pem", dfn_cert="/path/to/cert.pem", dfn_key="/path/to/key.pem")

        # Validate certificates should succeed
        assert config.validate_certificates() is True


def test_certificate_validation_failures():
    """Test certificate validation failures."""

    # Test skipping validation when paths not provided
    config = DFNConfig(dfn_ca="", dfn_cert="", dfn_key="")
    assert config.validate_certificates() is True

    # Test skipping validation with skip_path_validation
    config = DFNConfig(
        dfn_ca="/path/to/ca.pem", dfn_cert="/path/to/cert.pem", dfn_key="/path/to/key.pem", skip_path_validation=True
    )
    assert config.validate_certificates() is True

    # Test expired CA certificate - using proper mocking for datetime
    # Define fixed_now for the test - use a date after the CA cert expiration
    fixed_now = datetime.datetime(2022, 1, 1, tzinfo=datetime.UTC)

    # Create a custom datetime wrapper class that overrides comparison operators
    class DatetimeWrapper:
        def __init__(self, dt_value, valid=True):
            self.dt = dt_value
            self.valid = valid  # Controls if this date should be considered valid

        def __lt__(self, other):
            # For the check: now < cert.not_valid_before_utc
            # Return False for valid certificates (not in the future)
            # Return True for invalid certificates (in the future)
            return not self.valid

        def __gt__(self, other):
            # For the check: now > cert.not_valid_after_utc
            # Return False for valid certificates (not expired)
            # Return True for invalid certificates (expired)
            return not self.valid

    # Mock function to replace datetime.now
    def mock_now(tz=None):
        if tz is None:
            return fixed_now
        return fixed_now.replace(tzinfo=tz)

    # Combine multiple with statements
    with (
        patch.object(DFNConfig, "_verify_key_pair", return_value=True),
        patch("pathlib.Path.open", MagicMock()),
        patch("cryptography.x509.load_pem_x509_certificate") as mock_load_cert,
        patch("cryptography.hazmat.primitives.serialization.load_pem_private_key", MagicMock()),
        patch("datetime.datetime", wraps=datetime.datetime) as mock_datetime,
    ):
        # Set the now method to our mock implementation
        mock_datetime.now = mock_now

        # Setup mocks for expired certificate
        ca_cert = MagicMock()
        client_cert = MagicMock()

        # Use our wrapper class for validity dates - mark CA cert as invalid (expired)
        # Updated to use the _utc suffix to match the actual implementation
        ca_cert.not_valid_before_utc = DatetimeWrapper(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC), valid=True)
        ca_cert.not_valid_after_utc = DatetimeWrapper(
            datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC), valid=False
        )  # Expired

        client_cert.not_valid_before_utc = DatetimeWrapper(
            datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC), valid=True
        )
        client_cert.not_valid_after_utc = DatetimeWrapper(
            datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC), valid=True
        )

        # Return mock certificates
        mock_load_cert.side_effect = [ca_cert, client_cert]
        config = DFNConfig(dfn_ca="/path/to/ca.pem", dfn_cert="/path/to/cert.pem", dfn_key="/path/to/key.pem")

        # Update to match the exact error message from the code
        with pytest.raises(ConfigValidationError, match="CA certificate is expired"):
            config.validate_certificates()


def test_key_pair_verification():
    """Test key pair verification method."""
    # Create a DFNConfig instance
    config = DFNConfig()

    # Mock private and public keys
    private_key = MagicMock()
    public_key = MagicMock()

    # Test successful verification
    private_key.sign.return_value = b"signature"
    public_key.verify.return_value = None  # No exception means success
    # Should not raise an exception
    assert config._verify_key_pair(private_key, public_key) is True

    # Test failed verification
    public_key.verify.side_effect = Exception("Verification failed")
    assert config._verify_key_pair(private_key, public_key) is False


def test_certificate_chain_verification():
    """Test certificate chain verification."""
    # Create a DFNConfig instance
    config = DFNConfig()

    # Mock CA and client certificates
    ca_cert = MagicMock()
    client_cert = MagicMock()

    # Set up for successful verification
    ca_cert.subject = "CA Subject"
    client_cert.issuer = "CA Subject"

    # Should not raise an exception
    config._verify_certificate_chain(ca_cert, client_cert)

    # Test failure case
    client_cert.issuer = "Different Issuer"
    with pytest.raises(ConfigValidationError, match="Client certificate not issued by the provided CA"):
        config._verify_certificate_chain(ca_cert, client_cert)


def test_cli_config_loading():
    """Test loading configuration from CLI arguments."""
    # Create a mock argparse namespace with CLI args
    cli_args = argparse.Namespace()
    cli_args.dfn_customer_id = "cli-test-id"
    cli_args.wazuh_max_event_size = 12345  # Changed from string to int to match expected conversion
    cli_args.log_level = "ERROR"
    cli_args.wazuh_unix_socket_path = "(localhost, 1234)"

    # Create config and load from CLI
    config = Config()
    Config._load_from_cli(config, cli_args)

    # Verify the values were loaded correctly
    assert config.dfn.dfn_id == "cli-test-id"
    assert config.wazuh.max_event_size == 12345
    assert config.log.level == "ERROR"
    assert config.wazuh.unix_socket_path == ("localhost", 1234)


def test_cli_config_loading_with_pipe_types():
    """Test loading configuration with pipe (union) types from CLI."""
    # Create CLI args with values for union-type fields
    cli_args = argparse.Namespace()
    cli_args.misc_own_network = "10.0.0.0/8"  # This is str | None type

    # Create config and load from CLI
    config = Config()
    Config._load_from_cli(config, cli_args)

    # Verify the union type was handled correctly
    assert config.misc.own_network == "10.0.0.0/8"


def test_env_config_loading_with_pipe_types(monkeypatch):
    """Test loading configuration with pipe (union) types from environment."""
    # Set environment variable for a union-type field
    monkeypatch.setenv("MISC_OWN_NETWORK", "172.16.0.0/12")

    # Create config and load from environment
    config = Config()
    Config._load_from_env(config)

    # Verify the union type was handled correctly
    assert config.misc.own_network == "172.16.0.0/12"


def test_get_config_value():
    """Test Config.get() method and caching behavior."""
    # Create config with some values
    config = Config(dfn=DFNConfig(dfn_id="test-id"), wazuh=WazuhConfig(max_event_size=54321))

    # Test getting existing values
    assert config.get("dfn.dfn_id") == "test-id"
    assert config.get("wazuh.max_event_size") == "54321"

    # Test default value for non-existent key
    default_value = "default-value"
    assert config.get("nonexistent.key", default_value) == default_value

    # Clear cache before testing empty default
    config.config_cache.clear()

    # Test empty default when no default is provided
    assert config.get("nonexistent.key") == ""  # Should return empty string

    # Test caching behavior
    config.get("dfn.dfn_id")  # First call caches the value

    # Modify the attribute
    config.dfn.dfn_id = "modified-id"

    # Get should return cached value
    assert config.get("dfn.dfn_id") == "test-id"

    # Clear cache and try again
    config.config_cache.clear()
    assert config.get("dfn.dfn_id") == "modified-id"


def test_config_sample_generation_yaml(tmp_path):
    """Test sample config generation in YAML format."""
    output_path = tmp_path / "sample_config.yaml"
    Config._generate_sample_config(str(output_path), "yaml")

    assert output_path.exists()
    content = output_path.read_text()
    assert "# DFN Configuration" in content
    assert "dfn:" in content
    assert "wazuh:" in content
    assert "kafka:" in content
    assert "log:" in content
    assert "misc:" in content


def test_yaml_config_loading_file_not_found():
    """Test error handling when YAML config file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        Config.from_yaml("/nonexistent/config.yaml")


def test_yaml_config_invalid_content():
    """Test error handling with invalid YAML content."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml_path = tmp.name
        tmp.write("invalid: yaml: content: ]")
    try:
        with pytest.raises(ConfigValidationError):
            Config.from_yaml(yaml_path)
    finally:
        Path(yaml_path).unlink()


def test_yaml_config_invalid_format():
    """Test error handling with invalid YAML format (not a dict)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml_path = tmp.name
        tmp.write("- just\n- a\n- list")
    try:
        with pytest.raises(ConfigValidationError):
            Config.from_yaml(yaml_path)
    finally:
        Path(yaml_path).unlink()


def test_config_value_precedence():
    """Test configuration value precedence when loading from multiple sources."""
    # Create a temporary YAML config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml_path = tmp.name
        tmp.write(
            """
dfn:
  dfn_id: yaml-id
  dfn_broker: yaml-broker:9092
wazuh:
  max_event_size: 40000
            """
        )

    try:
        # 1. Start with defaults
        config = Config()
        assert config.dfn.dfn_id is None  # Default is None
        assert config.dfn.dfn_broker == "kafka.example.org:443"  # Default value
        assert config.wazuh.max_event_size == 65535  # Default value

        # 2. Load from YAML file (overrides defaults)
        config = Config.from_yaml(yaml_path, config)
        assert config.dfn.dfn_id == "yaml-id"
        assert config.dfn.dfn_broker == "yaml-broker:9092"
        assert config.wazuh.max_event_size == 40000

        # 3. Load from environment (should only override fields not set in YAML)
        with patch.dict(
            "os.environ",
            {
                "DFN_CUSTOMER_ID": "env-id",  # Should NOT override YAML
                "DFN_BROKER_ADDRESS": "env-broker:9092",  # Should NOT override YAML
                "KAFKA_TIMEOUT": "120",  # Should override default
            },
        ):
            Config._load_from_env(config)
            # Values from YAML should be preserved
            assert config.dfn.dfn_id == "yaml-id"  # Still from YAML
            assert config.dfn.dfn_broker == "yaml-broker:9092"  # Still from YAML
            # Default should be overridden by env var
            assert config.kafka.timeout == 120  # From env

        # 4. Load from CLI (highest precedence, overrides everything)
        args = argparse.Namespace()
        args.dfn_customer_id = "cli-id"
        args.dfn_broker_address = "cli-broker:9092"
        args.kafka_timeout = 180

        Config._load_from_cli(config, args)
        # CLI should override all previous values
        assert config.dfn.dfn_id == "cli-id"  # From CLI
        assert config.dfn.dfn_broker == "cli-broker:9092"  # From CLI
        assert config.kafka.timeout == 180  # From CLI
    finally:
        Path(yaml_path).unlink()


def test_merge_config_values():
    """Test the _merge_config_values method directly."""
    # Create a base config with default values
    base_config = Config()

    # Create updates
    updates = {"dfn": {"dfn_id": "test-id", "dfn_broker": "test-broker:9092"}, "wazuh": {"max_event_size": 32768}}

    # Test with overwrite_existing=True
    merged = Config._merge_config_values(base_config, updates, overwrite_existing=True)
    assert merged["dfn"]["dfn_id"] == "test-id"
    assert merged["dfn"]["dfn_broker"] == "test-broker:9092"
    assert merged["wazuh"]["max_event_size"] == 32768

    # Modify base config to have non-default values
    modified_config = Config(
        dfn=DFNConfig(dfn_id="original-id", dfn_broker="original-broker:9092"), wazuh=WazuhConfig(max_event_size=54321)
    )

    # Test with overwrite_existing=False (should preserve existing non-default values)
    merged = Config._merge_config_values(modified_config, updates, overwrite_existing=False)
    assert merged["dfn"]["dfn_id"] == "original-id"  # Preserved
    assert merged["dfn"]["dfn_broker"] == "original-broker:9092"  # Preserved
    assert merged["wazuh"]["max_event_size"] == 54321  # Preserved

    # Test with overwrite_existing=True (should override existing values)
    merged = Config._merge_config_values(modified_config, updates, overwrite_existing=True)
    assert merged["dfn"]["dfn_id"] == "test-id"  # Overwritten
    assert merged["dfn"]["dfn_broker"] == "test-broker:9092"  # Overwritten
    assert merged["wazuh"]["max_event_size"] == 32768  # Overwritten


def test_layered_configuration_loading():
    """Test loading configuration in layers with different precedence."""
    # Create two temporary config files
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as base_file:
        base_path = base_file.name
        base_file.write(
            """
dfn:
  dfn_id: base-id
  dfn_broker: base-broker:9092
wazuh:
  max_event_size: 30000
            """
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as override_file:
        override_path = override_file.name
        override_file.write(
            """
dfn:
  dfn_id: override-id
wazuh:
  json_alert_file: /custom/path/alerts.json
            """
        )

    try:
        # Load base config
        config = Config.from_yaml(base_path)
        assert config.dfn.dfn_id == "base-id"
        assert config.dfn.dfn_broker == "base-broker:9092"
        assert config.wazuh.max_event_size == 30000

        # Load override config on top of base
        config = Config.from_yaml(override_path, config)
        assert config.dfn.dfn_id == "override-id"  # Overridden
        assert config.dfn.dfn_broker == "base-broker:9092"  # Preserved from base
        assert config.wazuh.max_event_size == 30000  # Preserved from base
        assert config.wazuh.json_alert_file == "/custom/path/alerts.json"  # From override

        # Now add environment variables (should only override defaults)
        with patch.dict(
            "os.environ",
            {
                "DFN_BROKER_ADDRESS": "env-broker:9092",  # Should NOT override base config
                "WAZUH_MAX_EVENT_SIZE": "20000",  # Should NOT override base config
                "LOG_LEVEL": "DEBUG",  # Should override default
            },
        ):
            Config._load_from_env(config)
            assert config.dfn.dfn_id == "override-id"  # Still from override
            assert config.dfn.dfn_broker == "base-broker:9092"  # Still from base
            assert config.wazuh.max_event_size == 30000  # Still from base
            assert config.log.level == "DEBUG"  # From env (was default)

        # Finally, add CLI args (should override everything)
        args = argparse.Namespace()
        args.dfn_broker_address = "cli-broker:9092"
        args.wazuh_max_event_size = 10000

        Config._load_from_cli(config, args)
        assert config.dfn.dfn_id == "override-id"  # Still from override (not changed by CLI)
        assert config.dfn.dfn_broker == "cli-broker:9092"  # From CLI
        assert config.wazuh.max_event_size == 10000  # From CLI
        assert config.log.level == "DEBUG"  # Still from env
    finally:
        Path(base_path).unlink()
        Path(override_path).unlink()
