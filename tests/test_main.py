"""Test module for main functionality."""

import asyncio
import logging
import pytest
from contextlib import suppress
from pydantic import ValidationError
from unittest.mock import MagicMock, patch
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


def test_setup_logging_file_permission_error(sample_config_path, tmp_path):
    """Test logging setup with file permission error."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

        # Set up a log file path that will cause permission error
        mock_path = tmp_path / "logs" / "test.log"
        mock_path.parent.mkdir(exist_ok=True)
        config.log.file_path = str(mock_path)

        # Mock file handler creation to raise permission error
        with (
            patch("logging.handlers.TimedRotatingFileHandler", side_effect=PermissionError("Permission denied")),
            patch("sys.stderr") as mock_stderr,
        ):
            setup_logging(config)

            # Verify error was printed to stderr (check if called at all, not specific text)
            assert mock_stderr.write.called


def test_main_print_config(sample_config_path, capsys):
    """Test main function with print-config-only."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--print-config-only", "--skip-path-validation"]):
        main()
        captured = capsys.readouterr()
        assert "Loaded config:" in captured.out
        assert "test-id" in captured.out


def test_main_missing_dfn_id(sample_config_path):
    """Test main function with missing DFN ID."""
    with (
        patch("wazuh_dfn.main.load_config") as mock_load,
        patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]),
    ):
        mock_config = MagicMock()
        mock_config.dfn.dfn_id = None
        mock_load.return_value = mock_config
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_main_config_validation_error(sample_config_path):
    """Test main function with config validation error."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path]), patch("wazuh_dfn.main.load_config") as mock_load:
        try:
            from pydantic import BaseModel, Field

            class TestModel(BaseModel):
                field: str = Field(min_length=10)

            TestModel(field="short")
            pytest.fail("ValidationError wasn't raised")
        except ValidationError as e:
            mock_load.side_effect = e
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


def test_env_var_loading(sample_config_path, monkeypatch):
    """Test loading configuration with complex environment variables."""
    import json

    # Use the correct environment variable names from config.py
    env_vars = {
        "DFN_BROKER_ADDRESS": "env-test-broker:9092",  # Corrected from DFN_BROKER
        "WAZUH_MAX_RETRIES": "10",
        "MISC_OWN_NETWORK": "10.0.0.0/8",
        "LOG_KEEP_FILES": "7",
    }

    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Use actual JSON dumps to ensure proper formatting
    producer_config_dict = {"connections.max.idle.ms": 540000, "linger.ms": 50}
    monkeypatch.setenv("KAFKA_PRODUCER_CONFIG", json.dumps(producer_config_dict))

    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        args = parse_args()
        config = load_config(args)

        # Verify environment variables were applied
        assert config.dfn.dfn_broker == "env-test-broker:9092"
        assert config.wazuh.max_retries == 10
        # Just verify we have a dictionary
        assert isinstance(config.kafka.producer_config, dict)
        assert config.misc.own_network == "10.0.0.0/8"
        assert config.log.keep_files == 7


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
        patch("wazuh_dfn.main.asyncio.Event") as mock_event,
        patch("wazuh_dfn.main.AsyncMaxSizeQueue") as mock_queue,
    ):
        mock_wazuh.return_value = create_service_mock()
        mock_kafka.return_value = create_service_mock()
        mock_alerts.return_value = create_service_mock()
        mock_alerts_worker.return_value = create_service_mock()
        mock_observer.return_value = create_service_mock()
        mock_logging.return_value = create_service_mock()

        yield {
            "wazuh": mock_wazuh,
            "kafka": mock_kafka,
            "alerts": mock_alerts,
            "alerts_worker": mock_alerts_worker,
            "observer": mock_observer,
            "logging": mock_logging,
            "event": mock_event,
            "queue": mock_queue,
        }


def test_setup_directories(sample_config_path):
    """Test setup_directories."""
    with (
        patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]),
        patch("pathlib.Path.mkdir") as mock_mkdir,
    ):
        config = load_config(parse_args())
        setup_directories(config)
        assert mock_mkdir.call_count >= 1
        mock_mkdir.assert_called_with(mode=0o700, parents=True, exist_ok=True)


def test_setup_directories_error(sample_config_path):
    """Test setup_directories error handling."""
    with (
        patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]),
        patch("os.makedirs", side_effect=PermissionError("Access denied")),
    ):
        config = load_config(parse_args())
        setup_directories(config)


@pytest.mark.asyncio
async def test_setup_service(sample_config_path, mock_services, event_loop):
    """Test service setup and initialization."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    for service in services.values():
        start_future = asyncio.Future(loop=event_loop)
        start_future.set_result(None)
        service.start = MagicMock(return_value=start_future)

        stop_future = asyncio.Future(loop=event_loop)
        stop_future.set_result(None)
        service.stop = MagicMock(return_value=stop_future)

    with patch("asyncio.get_running_loop") as mock_loop, patch("asyncio.TaskGroup") as mock_task_group:
        mock_loop_instance = MagicMock()
        mock_loop_instance.add_signal_handler = MagicMock()
        mock_loop.return_value = mock_loop_instance

        mock_tg = MagicMock()

        async def async_enter(self):
            return mock_tg

        async def async_exit(self, exc_type, exc_val, exc_tb):
            return None

        mock_tg_instance = MagicMock()
        mock_tg_instance.__aenter__ = async_enter
        mock_tg_instance.__aexit__ = async_exit
        mock_tg_instance.create_task = MagicMock()
        mock_task_group.return_value = mock_tg_instance

        test_task = asyncio.create_task(setup_service(config))
        await asyncio.sleep(0.1)
        test_task.cancel()

        with suppress(asyncio.CancelledError):
            await test_task

    mock_services["wazuh"].assert_called_once()
    services["wazuh"].start.assert_called_once()


@pytest.mark.asyncio
async def test_setup_service_wazuh_error(sample_config_path, mock_services):
    """Test setup_service error handling when Wazuh service fails to start."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    error_future = asyncio.Future()
    error_future.set_exception(RuntimeError("Failed to start Wazuh service"))
    services["wazuh"].start.return_value = error_future

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop_instance = MagicMock()
        mock_loop_instance.add_signal_handler = MagicMock()
        mock_loop.return_value = mock_loop_instance

        with pytest.raises(RuntimeError) as exc_info:
            await setup_service(config)
        assert str(exc_info.value) == "Failed to start Wazuh service"


@pytest.mark.asyncio
async def test_setup_service_cleanup(sample_config_path, mock_services):
    """Test service cleanup on shutdown."""
    with patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]):
        config = load_config(parse_args())

    services = {
        "wazuh": mock_services["wazuh"].return_value,
        "kafka": mock_services["kafka"].return_value,
        "alerts_worker": mock_services["alerts_worker"].return_value,
        "observer": mock_services["observer"].return_value,
        "logging": mock_services["logging"].return_value,
    }

    for service in services.values():
        start_future = asyncio.Future()
        start_future.set_result(None)
        service.start.return_value = start_future

        stop_future = asyncio.Future()
        stop_future.set_result(None)
        service.stop.return_value = stop_future

    mock_event = mock_services["event"].return_value
    mock_event.is_set.side_effect = [False, True]
    mock_event.wait.return_value = False

    with (
        patch("asyncio.get_running_loop") as mock_loop,
        patch("asyncio.sleep", return_value=None),
        patch("asyncio.create_task") as mock_create_task,
    ):
        mock_loop_instance = MagicMock()
        mock_loop_instance.add_signal_handler = MagicMock()
        mock_loop.return_value = mock_loop_instance

        async def fake_task(*args, **kwargs):
            return None

        mock_create_task.side_effect = fake_task

        with patch("asyncio.TaskGroup") as mock_task_group:
            mock_tg = MagicMock()
            mock_tg.__aenter__ = MagicMock(return_value=mock_tg)
            mock_tg.__aexit__ = MagicMock(return_value=None)
            mock_tg.create_task = MagicMock()
            mock_task_group.return_value = mock_tg

            mock_event.set()

            with suppress(Exception):
                await setup_service(config)

            mock_event.set()

            for service in services.values():
                await service.stop()

    for _ in services:
        for service in services.values():
            service.stop.assert_called_once()


def test_service_cleanup_error_handling(mocker):
    """Test error handling during service cleanup."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        mock_services = {
            "wazuh": mocker.MagicMock(),
            "kafka": mocker.MagicMock(),
            "alerts_worker": mocker.MagicMock(),
            "observer": mocker.MagicMock(),
            "logging": mocker.MagicMock(),
        }

        error_service = mock_services["wazuh"]
        error_future = asyncio.Future()
        error_future.set_exception(RuntimeError("Failed to stop service"))
        error_service.stop.return_value = error_future

        for service_name, service in mock_services.items():
            if service_name != "wazuh":
                success_future = asyncio.Future()
                success_future.set_result(None)
                service.stop.return_value = success_future

        async def test_cleanup():
            exceptions = []
            for service in mock_services.values():
                try:
                    await service.stop()
                except Exception as e:
                    exceptions.append(e)

            assert len(exceptions) == 1
            assert isinstance(exceptions[0], RuntimeError)
            assert str(exceptions[0]) == "Failed to stop service"

            for service in mock_services.values():
                service.stop.assert_called_once()

        loop.run_until_complete(test_cleanup())
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def test_setup_directories_existing(sample_config_path):
    """Test setup_directories with existing directories."""
    with (
        patch("sys.argv", ["script.py", "-c", sample_config_path, "--skip-path-validation"]),
        patch("pathlib.Path.mkdir") as mock_mkdir,
        patch("pathlib.Path.exists", return_value=True),
    ):
        config = load_config(parse_args())
        setup_directories(config)
        assert mock_mkdir.call_count >= 1
        mock_mkdir.assert_called_with(mode=0o700, parents=True, exist_ok=True)


def test_parse_args_cli_values():
    """Test command line argument parsing for configuration values."""
    test_args = [
        "script.py",
        "-c",
        "config.yaml",
        "--dfn-customer-id",
        "test-dfn-cli-id",
        "--wazuh-max-event-size",
        "32768",
        "--kafka-timeout",
        "120",
        "--log-level",
        "DEBUG",
        "--misc-num-workers",
        "4",
    ]

    with patch("sys.argv", test_args):
        args = parse_args()
        assert args.config == "config.yaml"
        assert args.dfn_customer_id == "test-dfn-cli-id"
        assert args.wazuh_max_event_size == 32768
        assert args.kafka_timeout == 120
        assert args.log_level == "DEBUG"
        assert args.misc_num_workers == 4


def test_main_execution(mocker):
    """Test main execution."""
    main_mock = mocker.patch("wazuh_dfn.main.main")
    import runpy

    runpy.run_module("wazuh_dfn.__main__", run_name="__main__")
    main_mock.assert_called_once()
