"""Performance tests for alert processing."""

import ctypes
import gc
import json
import logging
import os
import queue
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from multiprocessing import Value
from pathlib import Path
from queue import Queue
from typing import List, TextIO
from unittest.mock import MagicMock

import pytest

from wazuh_dfn.config import MiscConfig, WazuhConfig
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.handlers.syslog_handler import SyslogHandler
from wazuh_dfn.services.handlers.windows_handler import WindowsHandler
from wazuh_dfn.services.kafka_service import KafkaService
from wazuh_dfn.services.wazuh_service import WazuhService

# Configure root logger
logging.getLogger().setLevel(logging.INFO)

# Configure file handler
log_file = "performance_test.log"
if os.path.exists(log_file):
    os.remove(log_file)

file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

# Configure console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Add handlers to root logger
logging.getLogger().addHandler(file_handler)
logging.getLogger().addHandler(console_handler)

LOGGER = logging.getLogger(__name__)
LOGGER.info("Performance test logging initialized")

MONITORED_EVENT_IDS = ["4625", "4719", "4964", "1102", "4794", "4724", "4697", "4702", "4698", "4672", "4720", "1100"]


def create_windows_alert(event_id: str) -> dict:
    """Create a sample Windows alert."""
    return {
        "timestamp": datetime.now().isoformat(),
        "id": f"test-{secrets.randbelow(9000) + 1000}",  # Generate number between 1000-9999
        "agent": {"id": "001", "name": "test-agent"},
        "data": {
            "win": {
                "system": {
                    "eventID": event_id,
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": datetime.now().isoformat(),
                    "computer": "test-computer",
                    "processID": str(secrets.randbelow(65535)),  # Random PID
                    "threadID": str(secrets.randbelow(65535)),  # Random TID
                },
                "eventdata": {
                    "subjectUserName": "SYSTEM",
                    "subjectDomainName": "NT AUTHORITY",
                    "subjectLogonId": "0x3e7",
                    "status": "0x0",
                    "failureReason": "%%2313",
                    "ipAddress": f"198.51.{secrets.randbelow(256)}.{secrets.randbelow(256)}",
                    "ipPort": str(secrets.randbelow(65535)),
                    "processName": "C:\\Windows\\System32\\svchost.exe",
                    "targetUserName": f"user-{secrets.randbelow(1000)}",
                    "workstationName": f"WKS-{secrets.randbelow(100)}",
                },
            }
        },
    }


def create_fail2ban_alert() -> dict:
    """Create a sample Fail2ban alert."""
    severity = secrets.choice(["NOTICE", "WARNING", "ERROR"])
    return {
        "timestamp": datetime.now().isoformat(),
        "id": f"test-{secrets.randbelow(9000) + 1000}",
        "agent": {"id": "001", "name": "test-agent"},
        "rule": {"level": 5, "description": "Fail2ban: Host banned", "groups": ["fail2ban"]},
        "data": {
            "srcip": f"198.51.{secrets.randbelow(256)}.{secrets.randbelow(256)}",
            "program_name": "fail2ban.actions",
            "severity": severity,
            "pid": str(secrets.randbelow(65535)),
        },
        "full_log": f"fail2ban: {datetime.now().isoformat()} fail2ban.actions: {severity} [sshd] Ban 198.51.100.1",
    }


def generate_mixed_alerts(count: int) -> List[dict]:
    """Generate a mix of Windows and Fail2ban alerts."""
    alerts = []

    # Calculate distribution (1/3 each for windows-monitored, windows-unmonitored, fail2ban)
    win_monitored_count = count // 3
    win_unmonitored_count = count // 3
    fail2ban_count = count - win_monitored_count - win_unmonitored_count

    # Generate monitored Windows alerts
    for _ in range(win_monitored_count):
        event_id = secrets.choice(MONITORED_EVENT_IDS)
        alerts.append(create_windows_alert(event_id))

    # Generate unmonitored Windows alerts
    for _ in range(win_unmonitored_count):
        while True:
            event_id = str(secrets.randbelow(9000) + 1000)  # Generate between 1000-9999
            if event_id not in MONITORED_EVENT_IDS:
                break
        alerts.append(create_windows_alert(event_id))

    # Generate Fail2ban alerts
    for _ in range(fail2ban_count):
        alerts.append(create_fail2ban_alert())

    # Securely shuffle the alerts
    shuffled = list(alerts)
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled


class MockKafkaService(KafkaService):
    """Mock Kafka service that counts messages by type."""

    def __init__(self):
        self.windows_count = 0
        self.fail2ban_count = 0
        self.lock = threading.Lock()

    def send_message(self, message):
        with self.lock:
            if "win" in message.get("data", {}):
                self.windows_count += 1
            elif message.get("event_format") == "syslog5424-json":
                self.fail2ban_count += 1
        return True


class AlertWriter:
    """Writes alerts to file at specified rate."""

    def __init__(self, file_path: str, alerts_per_second: int):
        self.file_path = file_path
        self.alerts_per_second = alerts_per_second
        self.running = False
        self._stop_event = threading.Event()
        self.buffer_size = max(alerts_per_second * 2, 10000)  # Buffer 2 seconds worth of alerts
        LOGGER.info(f"Initializing AlertWriter with target rate: {alerts_per_second}/s")

    def start(self):
        """Start writing alerts to file."""
        self.running = True
        with open(self.file_path, "w", encoding="utf-8", buffering=self.buffer_size) as f:
            while not self._stop_event.is_set():
                batch_start = time.time()
                self._write_batch(f)
                elapsed = time.time() - batch_start
                if elapsed < 1.0:
                    time.sleep(1.0 - elapsed)

    def _write_batch(self, f: TextIO):
        """Write one second worth of alerts."""
        batch_start = time.time()
        alerts = generate_mixed_alerts(self.alerts_per_second)
        generation_time = time.time() - batch_start

        write_start = time.time()
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
        write_time = time.time() - write_start

        LOGGER.debug(f"Batch stats - Generation: {generation_time:.3f}s, Writing: {write_time:.3f}s")

    def stop(self):
        """Stop writing alerts."""
        self._stop_event.set()
        self.running = False


def process_alert(args):
    """Process a single alert with the appropriate handler."""
    alert, windows_handler, syslog_handler, windows_count, fail2ban_count = args
    if "win" in alert.get("data", {}):
        windows_handler.process_alert(alert)
        if alert["data"]["win"]["system"]["eventID"] in MONITORED_EVENT_IDS:
            with windows_count.get_lock():
                windows_count.value += 1
    elif "program_name" in alert.get("data", {}) and alert["data"]["program_name"] == "fail2ban.actions":
        syslog_handler.process_alert(alert)
        with fail2ban_count.get_lock():
            fail2ban_count.value += 1
    return True


@pytest.mark.performance(threshold="1000/s", description="Mixed alert processing throughput test")
def test_mixed_alerts_performance():  # NOSONAR
    """Test processing 1000 mixed alerts/second from file."""
    LOGGER.info("=" * 80)
    LOGGER.info("Starting new performance test run")
    LOGGER.info("=" * 80)

    LOGGER.info("Starting performance test")
    # Test parameters
    duration = 60  # Run for 60 seconds
    alerts_per_second = 1000
    num_workers = 10

    # Create temporary alert file
    alert_file = Path(os.path.join(os.getcwd(), "test_alerts.json"))
    if alert_file.exists():
        try:
            # Force close any open handles before deletion
            gc.collect()  # Collect any lingering file handles
            if hasattr(alert_file, "_handle"):
                alert_file._handle.close()
            alert_file.unlink()
        except PermissionError as e:
            LOGGER.warning(f"Could not delete existing file: {e}")
            return  # Skip test if file cannot be deleted

    try:
        # Initialize services
        LOGGER.info(f"Initializing test with {num_workers} workers")
        alert_queue = Queue(maxsize=alerts_per_second * 4)  # Increased queue size
        kafka_service = MockKafkaService()
        wazuh_service = MagicMock(spec=WazuhService)
        windows_handler = WindowsHandler(kafka_service, wazuh_service)
        syslog_handler = SyslogHandler(MiscConfig(), kafka_service, wazuh_service)

        # Shared counters using multiprocessing.Value
        windows_count = Value(ctypes.c_int, 0)
        fail2ban_count = Value(ctypes.c_int, 0)

        # Configure and start alert writer
        writer = AlertWriter(str(alert_file), alerts_per_second)
        writer_thread = threading.Thread(target=writer.start)
        writer_thread.start()

        # Configure watcher service
        config = WazuhConfig()
        config.json_alert_file = str(alert_file)

        # Start watcher service
        watcher = AlertsWatcherService(config, alert_queue, threading.Event())
        watcher_thread = threading.Thread(target=watcher.start)
        watcher_thread.start()

        LOGGER.info("Starting alert processing")
        start_time = time.time()
        last_log = start_time
        processed = 0
        last_processed = 0

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            try:
                while time.time() - start_time < duration:
                    try:
                        alert = alert_queue.get(timeout=1.0)
                        futures.append(
                            executor.submit(
                                process_alert, (alert, windows_handler, syslog_handler, windows_count, fail2ban_count)
                            )
                        )
                        processed += 1

                        # Log progress every 5 seconds
                        current_time = time.time()
                        if current_time - last_log >= 5:
                            elapsed = current_time - last_log
                            current_rate = (processed - last_processed) / elapsed
                            queue_size = alert_queue.qsize()
                            LOGGER.info(
                                f"Progress - Processed: {processed}, "
                                f"Current rate: {current_rate:.1f}/s, "
                                f"Queue size: {queue_size}"
                            )
                            last_log = current_time
                            last_processed = processed

                        alert_queue.task_done()
                    except queue.Empty:
                        LOGGER.debug("Queue empty, waiting for alerts")
                        continue

            finally:
                LOGGER.info("Stopping alert generation and processing")
                writer.stop()
                writer_thread.join(timeout=5)
                watcher.shutdown_event.set()
                if hasattr(watcher.json_reader, "file_queue"):
                    watcher.json_reader.file_queue.close()
                watcher_thread.join(timeout=5)

                # Wait for all processing to complete
                for future in futures:
                    future.result(timeout=5)

        total_time = time.time() - start_time

        # Verify results
        actual_rate = processed / total_time
        processed_windows = kafka_service.windows_count
        processed_fail2ban = kafka_service.fail2ban_count

        # Calculate lost alerts
        lost_windows = windows_count.value - processed_windows
        lost_fail2ban = fail2ban_count.value - processed_fail2ban
        total_lost = lost_windows + lost_fail2ban

        LOGGER.info(f"Test duration: {total_time:.2f} seconds")
        LOGGER.info(f"Processed {processed} alerts")
        LOGGER.info(f"Average rate: {actual_rate:.2f} alerts/second")
        LOGGER.info(f"Windows alerts processed: {processed_windows}/{windows_count.value} (lost: {lost_windows})")
        LOGGER.info(f"Fail2ban alerts processed: {processed_fail2ban}/{fail2ban_count.value} (lost: {lost_fail2ban})")
        LOGGER.info(f"Total lost alerts: {total_lost}")

        # Assertions
        assert (
            actual_rate >= alerts_per_second * 0.95
        ), f"Processing rate {actual_rate:.2f} below target {alerts_per_second}"
        assert (
            processed_windows >= windows_count.value * 0.99
        ), f"Lost too many Windows alerts: {lost_windows} ({(lost_windows/windows_count.value)*100:.1f}%)"
        assert (
            processed_fail2ban >= fail2ban_count.value * 0.99
        ), f"Lost too many Fail2ban alerts: {lost_fail2ban} ({(lost_fail2ban/fail2ban_count.value)*100:.1f}%)"

    finally:
        # Cleanup test file with proper handle closure
        try:
            if alert_file.exists():
                # Force close any remaining handles
                gc.collect()
                if hasattr(alert_file, "_handle"):
                    alert_file._handle.close()
                alert_file.unlink()
        except PermissionError as e:
            LOGGER.error(f"Could not delete test file: {e}")
            LOGGER.error("Manual cleanup of {alert_file} may be required")
