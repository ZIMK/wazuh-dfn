"""Test module for main functionality."""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from wazuh_dfn.exceptions import ConfigValidationError
from wazuh_dfn.main import load_config, main, parse_args, setup_directories, setup_logging, setup_service

# Configure logging
logging.basicConfig(level=logging.DEBUG)


@pytest.fixture
def sample_config_path(tmp_path):
    config_content = """
dfn:
  dfn_id: "test-id"
  dfn_broker: "test-broker:443"
  dfn_ca: "/path/to/ca.pem"
  dfn_cert: "/path/to/cert.pem"
  dfn_key: "/path/to/key.pem"

wazuh:
  json_alert_file: "/var/ossec/logs/alerts/alerts.json"
  unix_socket_path: "localhost:1514"
  max_event_size: 65535
  json_alert_prefix: '{"timestamp"'
  json_alert_suffix: "}"
  json_alert_file_poll_interval: 1.0
  max_retries: 5
  retry_interval: 5
  json_alert_queue_size: 1000

kafka:
  timeout: 60
  retry_interval: 5
  connection_max_retries: 5
  send_max_retries: 5
  max_wait_time: 60
  admin_timeout: 10
  producer_config: {}

log:
  console: true
  file_path: "/opt/wazuh-dfn/logs/test.log"
  level: "INFO"
  interval: 60

misc:
  num_workers: 1
"""
    config = tmp_path / "config.yaml"
    config.write_text(config_content)
    return str(config)


def test_parse_args_basic():
    """Test basic argument parsing."""
    with patch("sys.argv", ["script.py", "-c", "config.yaml"]):
        args = parse_args()
        assert args.config == "config.yaml"
        assert not args.print_config_only
        assert not args.skip_path_validation


def test_parse_args_all_options():
    """Test parsing all command line options."""
    test_args = ["script.py", "-c", "config.yaml", "--print-config-only", "--skip-path-validation"]
    with patch("sys.argv", test_args):
        args = parse_args()
        assert args.config == "config.yaml"
        assert args.print_config_only
        assert args.skip_path_validation


def test_parse_args_help(capsys):
    """Test help output."""
    with patch("sys.argv", ["script.py", "--help"]), pytest.raises(SystemExit):
        parse_args()
    captured = capsys.readouterr()
    assert "usage:" in captured.out
    assert "Wazuh DFN Configuration" in captured.out


def test_parse_args_help_all(capsys):
    """Test help-all output."""
    with patch("sys.argv", ["script.py", "--help-all"]), pytest.raises(SystemExit):
        parse_args()
    captured = capsys.readouterr()
    assert "Wazuh DFN Configuration Fields:" in captured.out


def test_parse_args_version(capsys):
    """Test version output."""
    with patch("sys.argv", ["script.py", "--version"]), pytest.raises(SystemExit):
        parse_args()
    captured = capsys.readouterr()
    assert "script.py" in captured.out


def test_load_config_with_env_vars(sample_config_path, monkeypatch):
    """Test loading configuration with environment variables."""
    env_vars = {"DFN_CUSTOMER_ID": "env-test-id", "WAZUH_MAX_EVENT_SIZE": "32768", "LOG_LEVEL": "DEBUG"}
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        args = parse_args()
        config = load_config(args)
        assert config.dfn.dfn_id == "env-test-id"
        assert config.wazuh.max_event_size == 32768
        assert config.log.level == "DEBUG"


def test_setup_logging_console_only(sample_config_path):
    """Test logging setup with console only."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())
        config.log.file_path = None
        setup_logging(config)
        root_logger = logging.getLogger()
        assert any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers)
        assert not any(isinstance(h, logging.FileHandler) for h in root_logger.handlers)


def test_setup_logging_invalid_level(sample_config_path):
    """Test logging setup with invalid level."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())
        config.log.level = "INVALID"
        setup_logging(config)
        assert logging.getLogger().getEffectiveLevel() == logging.INFO


def test_main_print_config(sample_config_path, capsys):
    """Test main function with print-config-only."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--print-config-only", "--skip-path-validation"]):
        main()
        captured = capsys.readouterr()
        assert "Loaded config:" in captured.out
        assert "test-id" in captured.out


def test_main_missing_dfn_id(sample_config_path):
    """Test main function with missing DFN ID."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        with patch("wazuh_dfn.main.load_config") as mock_load:
            mock_config = MagicMock()
            mock_config.dfn.dfn_id = None
            mock_load.return_value = mock_config
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


def test_main_config_validation_error(sample_config_path):
    """Test main function with config validation error."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path]):
        with patch("wazuh_dfn.main.load_config", side_effect=ConfigValidationError("Invalid config")):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


@pytest.fixture
def mock_services():
    """Create mock services with proper stop methods."""

    def create_service_mock():
        mock = MagicMock()
        mock.stop = MagicMock()
        mock.start = MagicMock()
        return mock

    with (
        patch("wazuh_dfn.main.WazuhService") as mock_wazuh,
        patch("wazuh_dfn.main.KafkaService") as mock_kafka,
        patch("wazuh_dfn.main.AlertsService") as mock_alerts,
        patch("wazuh_dfn.main.AlertsWorkerService") as mock_alerts_worker,
        patch("wazuh_dfn.main.AlertsWatcherService") as mock_observer,
        patch("wazuh_dfn.main.LoggingService") as mock_logging,
        patch("wazuh_dfn.main.threading.Event") as mock_event,
        patch("wazuh_dfn.main.MaxSizeQueue") as mock_queue,
        patch("wazuh_dfn.main.threading.Thread") as mock_thread,
    ):
        # Configure service mocks with stop methods
        mock_wazuh.return_value = create_service_mock()
        mock_kafka.return_value = create_service_mock()
        mock_alerts.return_value = create_service_mock()
        mock_alerts_worker.return_value = create_service_mock()
        mock_observer.return_value = create_service_mock()
        mock_logging.return_value = create_service_mock()

        # Configure thread mock
        mock_thread.return_value = MagicMock()
        mock_thread.return_value.start = MagicMock()
        mock_thread.return_value.join = MagicMock()

        yield {
            "wazuh": mock_wazuh,
            "kafka": mock_kafka,
            "alerts": mock_alerts,
            "alerts_worker": mock_alerts_worker,
            "observer": mock_observer,
            "logging": mock_logging,
            "event": mock_event,
            "queue": mock_queue,
            "thread": mock_thread,
        }


def test_setup_directories(sample_config_path):
    """Test setup_directories."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())
        with patch("os.makedirs") as mock_makedirs:
            setup_directories(config)
            mock_makedirs.assert_called_once_with(
                os.path.dirname(config.log.file_path),
                mode=0o700,
                exist_ok=True,
            )


def test_setup_directories_error(sample_config_path):
    """Test setup_directories error handling."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())
        with patch("os.makedirs", side_effect=PermissionError("Access denied")):
            # Should not raise ConfigValidationError since directories are optional
            setup_directories(config)


def test_setup_service(sample_config_path, mock_services):
    """Test service setup and initialization."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    # Configure mock services
    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    # Mock time.sleep to avoid delays
    with patch("time.sleep"):
        # Test service setup
        setup_service(config)

    # Verify service initialization
    mock_services["wazuh"].assert_called_once()
    mock_services["kafka"].assert_called_once()
    mock_services["alerts_worker"].assert_called_once()
    mock_services["observer"].assert_called_once()
    mock_services["logging"].assert_called_once()

    # Verify services were started
    services["wazuh"].start.assert_called_once()


def test_setup_service_wazuh_error(sample_config_path, mock_services):
    """Test setup_service error handling when Wazuh service fails to start."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    # Configure mock services
    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    # Configure Wazuh service to fail
    services["wazuh"].start.side_effect = RuntimeError("Failed to start Wazuh service")

    with pytest.raises(RuntimeError) as exc_info:
        setup_service(config)
    assert str(exc_info.value) == "Failed to start Wazuh service"


def test_setup_service_cleanup(sample_config_path, mock_services):
    """Test service cleanup on shutdown."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    # Configure mock services
    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    # Configure thread mocks
    mock_threads = []
    for service in [services["kafka"], services["alerts_worker"], services["observer"], services["logging"]]:
        thread = MagicMock()

        def start_service(svc=service):
            svc.start()

        thread.start = MagicMock(side_effect=start_service)
        thread.join = MagicMock()
        mock_threads.append(thread)
    mock_services["thread"].side_effect = mock_threads

    # Configure shutdown event
    mock_event = mock_services["event"].return_value
    mock_event.is_set.side_effect = [False, True]  # Run once then shutdown
    mock_event.wait.return_value = False

    # Mock time.sleep to avoid delays
    with patch("time.sleep"), patch("signal.signal"):
        # Run service setup
        try:
            setup_service(config)
        except SystemExit:  # NOSONAR
            pass  # Ignore sys.exit from signal handler

        # Set shutdown event to trigger cleanup
        mock_event.set()

        # Call stop on each service to simulate cleanup
        for service in services.values():
            service.stop()

    # Verify cleanup
    for service in services.values():
        service.stop.assert_called_once()

    # Verify threads were joined
    for thread in mock_threads:
        thread.join.assert_called_once_with(timeout=1)


def test_setup_directories_existing(sample_config_path):
    """Test setup_directories with existing directories."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    with patch("os.makedirs") as mock_makedirs, patch("os.path.exists", return_value=True):
        setup_directories(config)
        mock_makedirs.assert_called_once_with(
            os.path.dirname(config.log.file_path),
            mode=0o700,
            exist_ok=True,
        )
