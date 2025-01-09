"""Performance tests for alert processing."""

import sys

if sys.version_info < (3, 12):
    raise RuntimeError("This code requires Python 3.12 or higher")

import ctypes
import gc
import json
import logging
import os
import platform
import queue
import secrets
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from multiprocessing import Value
from pathlib import Path
from queue import Empty, Queue
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
logging.getLogger().setLevel(logging.DEBUG)  # Set root to DEBUG to capture all

# Configure regular file handler (INFO level)
log_file = "performance_test.log"
if os.path.exists(log_file):
    os.remove(log_file)

file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

# Configure debug file handler (DEBUG level)
debug_log_file = "performance_test_debug.log"
if os.path.exists(debug_log_file):
    os.remove(debug_log_file)

debug_file_handler = logging.FileHandler(debug_log_file)
debug_file_handler.setLevel(logging.DEBUG)
debug_file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]")
)

# Configure console handler (INFO level)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Add handlers to root logger
logging.getLogger().addHandler(file_handler)
logging.getLogger().addHandler(debug_file_handler)
logging.getLogger().addHandler(console_handler)

LOGGER = logging.getLogger(__name__)
LOGGER.info("Performance test logging initialized")
LOGGER.debug("Debug logging initialized")

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


class AlertWriter(threading.Thread):
    """Writes alerts to file at specified rate."""

    def __init__(self, file_path: str, alerts_per_second: int):
        super().__init__()
        self.file_path = file_path
        self.alerts_per_second = alerts_per_second
        self.running = False
        self._stop_event = threading.Event()
        self.buffer_size = max(alerts_per_second * 2, 10000)  # Buffer 2 seconds worth of alerts
        self.total_bytes = 0
        self.alert_count = 0
        self.newline_bytes = 0
        self._file = None
        self._force_quit_timer = None
        self.newline_size = 2 if platform.system() == "Windows" else 1  # CRLF vs LF
        self._lock = threading.Lock()
        LOGGER.info(f"Initializing AlertWriter with target rate: {alerts_per_second}/s")
        LOGGER.debug(f"Using newline size: {self.newline_size} bytes")

    def run(self):
        """Start writing alerts to file with force quit timer."""
        self.running = True
        with open(self.file_path, "w", encoding="utf-8", buffering=self.buffer_size) as self._file:
            # Set force quit timer
            self._force_quit_timer = threading.Timer(70, self._force_quit)  # Force quit after 70s
            self._force_quit_timer.daemon = True
            self._force_quit_timer.start()
            try:
                while not self._stop_event.is_set():
                    batch_start = time.time()
                    self._write_batch(self._file)
                    elapsed = time.time() - batch_start
                    if elapsed < 1.0:
                        time.sleep(1.0 - elapsed)
            finally:
                if self._force_quit_timer and self._force_quit_timer.is_alive():
                    self._force_quit_timer.cancel()

    def _write_batch(self, f: TextIO):
        """Write one second worth of alerts."""
        batch_start = time.time()
        alerts = generate_mixed_alerts(self.alerts_per_second)
        generation_time = time.time() - batch_start

        write_start = time.time()
        for alert in alerts:
            alert_str = json.dumps(alert) + "\n"
            json_bytes = len(alert_str.encode("utf-8"))
            # Account for actual newline bytes on the system
            self.total_bytes += json_bytes - 1 + self.newline_size  # -1 for \n, +newline_size for actual ending
            self.newline_bytes += self.newline_size
            self.alert_count += 1
            with self._lock:
                if f and not f.closed:
                    f.write(alert_str)
                else:
                    raise ValueError("File handle is closed or invalid")

        write_time = time.time() - write_start

        LOGGER.debug(
            f"Batch stats - Generation: {generation_time:.3f}s, "
            f"Writing: {write_time:.3f}s, "
            f"Batch size: {len(alerts)} alerts"
        )

    def stop(self):
        """Stop writing alerts."""
        self._stop_event.set()
        self.running = False

    def _force_quit(self):
        """Force quit the process if it's stuck."""
        LOGGER.error("Force quitting due to timeout")
        if platform.system() == "Windows":
            os._exit(1)  # Force exit on Windows
        else:
            os.kill(os.getpid(), signal.SIGKILL)  # Force kill on Unix


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
        writer.start()
        writer.join()  # Wait for thread to complete

        # Configure watcher service
        config = WazuhConfig()
        config.json_alert_file = str(alert_file)

        # Start watcher service with explicit shutdown event
        watcher_shutdown = threading.Event()
        watcher = AlertsWatcherService(config, alert_queue, watcher_shutdown)
        watcher_thread = threading.Thread(target=watcher.start)
        watcher_thread.start()

        LOGGER.info("Starting alert processing")
        start_time = time.time()
        last_log = start_time
        processed = 0
        last_processed = 0

        # Set a timeout for the entire test
        test_timeout = time.time() + duration + 30  # duration + 30 seconds grace period

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            try:
                while time.time() - start_time < duration and time.time() < test_timeout:
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
                LOGGER.info("Starting shutdown sequence...")

                # Set timeout for entire shutdown sequence
                shutdown_deadline = time.time() + 15  # 15 seconds maximum for shutdown

                def is_timeout():
                    return time.time() > shutdown_deadline

                # 1. Stop writer with timeout
                writer.stop()
                writer.join(timeout=2)

                # 2. Force stop watcher
                watcher_shutdown.set()
                if hasattr(watcher, "json_reader"):
                    try:
                        watcher.json_reader.close()
                    except Exception:
                        pass

                # 3. Aggressive queue clearing
                while not alert_queue.empty() and not is_timeout():
                    try:
                        alert_queue.get_nowait()
                        alert_queue.task_done()
                    except Empty:
                        break

                # 4. Quick watcher thread cleanup
                watcher_thread.join(timeout=2)

                # 5. Cancel all pending futures immediately
                for future in futures:
                    future.cancel()

                # 6. Final executor shutdown
                LOGGER.info("Shutting down thread pool...")
                executor.shutdown(wait=False)  # Don't wait if tasks are still running

                LOGGER.info("Shutdown sequence completed")

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

        # After the test completes, verify file size matches bytes written
        actual_file_size = alert_file.stat().st_size
        LOGGER.info(f"Total bytes written (counted): {writer.total_bytes}")
        LOGGER.info(f"Total alerts written: {writer.alert_count}")
        LOGGER.info(f"Total newline bytes: {writer.newline_bytes}")
        LOGGER.info(f"Actual file size: {actual_file_size}")

        # Read the file content for verification
        with open(alert_file, "rb") as f:
            content = f.read()
            last_bytes = content[-10:] if len(content) >= 10 else content
            LOGGER.info(f"Last few bytes (hex): {last_bytes.hex()}")

            # Count actual newlines
            actual_newlines = content.count(b"\n")
            LOGGER.info(f"Actual newlines in file: {actual_newlines}")
            LOGGER.info(f"Expected newlines: {writer.alert_count}")

        # Detailed mismatch information
        if actual_file_size != writer.total_bytes:
            diff = actual_file_size - writer.total_bytes
            LOGGER.error(
                f"Size mismatch details:\n"
                f"Difference: {diff} bytes\n"
                f"Per alert difference: {diff / writer.alert_count:.2f} bytes\n"
                f"Newline difference: {actual_newlines - writer.alert_count}"
            )

        assert actual_file_size == writer.total_bytes, (
            f"File size mismatch. Written: {writer.total_bytes}, "
            f"Actual: {actual_file_size}, "
            f"Difference: {abs(writer.total_bytes - actual_file_size)} bytes"
        )

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
        # Enhanced cleanup with timeouts
        LOGGER.info("Performing final cleanup")
        try:
            writer.stop()
            watcher_shutdown.set()
            if hasattr(watcher, "json_reader"):
                try:
                    watcher.json_reader.close()
                except Exception as e:
                    LOGGER.error(f"Error closing json reader: {e}")

            # Force thread termination if needed
            if writer.is_alive():
                LOGGER.warning("Writer thread still alive during cleanup")
            if watcher_thread.is_alive():
                LOGGER.warning("Watcher thread still alive during cleanup")
        except Exception as e:
            LOGGER.error(f"Error during service cleanup: {e}")

        # Cleanup test file with proper handle closure and retries
        for _ in range(3):  # Try up to 3 times
            try:
                if alert_file.exists():
                    gc.collect()  # Force garbage collection
                    alert_file.unlink()
                    break
            except PermissionError as e:
                LOGGER.warning(f"Retry deleting file due to: {e}")
                time.sleep(1)  # Wait before retry
            except Exception as e:
                LOGGER.error(f"Unexpected error during file cleanup: {e}")
                break
