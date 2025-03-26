import json
from pathlib import Path
from unittest.mock import patch


def load_json_file(file_path: str) -> dict:
    with Path(file_path).open() as f:
        return json.load(f)


def test_process_fail2ban_alerts(alerts_service) -> None:
    """Test processing of fail2ban alerts from test JSON files"""
    # Get the directory where this test file is located
    test_dir = Path(__file__).parent

    # Combine the nested with statements into a single with statement
    with (
        patch.object(alerts_service.syslog_handler.kafka_service, "send_message") as mock_kafka_send,
        patch.object(alerts_service.syslog_handler.wazuh_service, "send_event") as mock_wazuh_send,
    ):
        # Mock successful Kafka send
        mock_kafka_send.return_value = {"success": True, "topic": "test-topic"}
        mock_wazuh_send.return_value = True

        fail2ban_files = [
            f for f in test_dir.iterdir() if f.name.startswith("lin_fail2ban-") and f.name.endswith(".json")
        ]

        for file_path in fail2ban_files:
            with file_path.open() as f:
                alert_data = json.load(f)
                alerts_service.process_alert(alert_data)

                if file_path.name == "lin_fail2ban-1.json":
                    # Verify Kafka and Wazuh were called
                    mock_kafka_send.assert_not_called()
                    mock_wazuh_send.assert_not_called()
                else:
                    # Verify Kafka and Wazuh were called
                    mock_kafka_send.assert_called_once()
                    mock_wazuh_send.assert_called_once()

                    # Verify message format
                    call_args = mock_kafka_send.call_args[0][0]
                    assert isinstance(call_args, dict)
                    assert "timestamp" in call_args
                    assert "body" in call_args
                    assert "event_format" in call_args
                    assert call_args["event_format"] == "syslog5424-json"

                # Reset mocks for next file
                mock_kafka_send.reset_mock()
                mock_wazuh_send.reset_mock()


def test_process_windows_alerts(alerts_service) -> None:
    """Test processing of Windows security alerts from test JSON files"""
    # Get the directory where this test file is located
    test_dir = Path(__file__).parent

    # Combine the nested with statements into a single with statement
    with (
        patch.object(alerts_service.windows_handler.kafka_service, "send_message") as mock_kafka_send,
        patch.object(alerts_service.windows_handler.wazuh_service, "send_event") as mock_wazuh_send,
    ):
        # Mock successful Kafka send
        mock_kafka_send.return_value = {"success": True, "topic": "test-topic"}
        mock_wazuh_send.return_value = True

        windows_files = [f for f in test_dir.iterdir() if f.name.startswith("win_") and f.name.endswith(".json")]

        for file_path in windows_files:
            with file_path.open() as f:
                alert_data = json.load(f)
                alerts_service.process_alert(alert_data)

                # Verify Kafka and Wazuh were called
                mock_kafka_send.assert_called_once()
                mock_wazuh_send.assert_called_once()

                # Verify message format
                call_args = mock_kafka_send.call_args[0][0]
                assert isinstance(call_args, dict)
                assert "timestamp" in call_args
                assert "body" in call_args

                # Reset mocks for next file
                mock_kafka_send.reset_mock()
                mock_wazuh_send.reset_mock()
