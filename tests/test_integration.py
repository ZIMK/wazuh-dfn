import json
import os
from typing import Dict
from unittest.mock import patch


def load_json_file(file_path: str) -> Dict:
    with open(file_path, "r") as f:
        return json.load(f)


def test_process_fail2ban_alerts(alerts_service) -> None:
    """Test processing of fail2ban alerts from test JSON files"""
    # Get the directory where this test file is located
    test_dir = os.path.dirname(os.path.abspath(__file__))

    # Mock Kafka producer to prevent actual message sending
    with patch.object(alerts_service.syslog_handler.kafka_service, "send_message") as mock_kafka_send:
        # Mock successful Kafka send
        mock_kafka_send.return_value = {"success": True, "topic": "test-topic"}

        # Mock Wazuh service to prevent actual event sending
        with patch.object(alerts_service.syslog_handler.wazuh_service, "send_event") as mock_wazuh_send:
            mock_wazuh_send.return_value = True

            fail2ban_files = [f for f in os.listdir(test_dir) if f.startswith("lin_fail2ban-") and f.endswith(".json")]

            for file_name in fail2ban_files:
                with open(os.path.join(test_dir, file_name), "r") as f:
                    alert_data = json.load(f)
                    alerts_service.process_alert(alert_data)

                    if file_name == "lin_fail2ban-1.json":
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
    test_dir = os.path.dirname(os.path.abspath(__file__))

    # Mock Kafka producer to prevent actual message sending
    with patch.object(alerts_service.windows_handler.kafka_service, "send_message") as mock_kafka_send:
        # Mock successful Kafka send
        mock_kafka_send.return_value = {"success": True, "topic": "test-topic"}

        # Mock Wazuh service to prevent actual event sending
        with patch.object(alerts_service.windows_handler.wazuh_service, "send_event") as mock_wazuh_send:
            mock_wazuh_send.return_value = True

            windows_files = [f for f in os.listdir(test_dir) if f.startswith("win_") and f.endswith(".json")]

            for file_name in windows_files:
                with open(os.path.join(test_dir, file_name), "r") as f:
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
