"""Performance Testing Suite for Wazuh DFN Alert Processing.

This module provides comprehensive performance testing for the Wazuh DFN alert processing pipeline,
focusing on throughput and reliability under high load conditions.

Key Features:
- Mixed alert type processing (Windows Security, Fail2ban)
- Configurable alert generation rates and test duration
- Concurrent read/write operations simulation
- Detailed performance metrics and logging
- Graceful shutdown handling

Test Configuration:
    - TEST_DURATION: Test runtime in seconds (default: 60)
    - TEST_ALERTS_PER_SECOND: Target alert processing rate (default: 1000)
    - TEST_NUM_WORKERS: Number of worker threads (default: 10)
    - TEST_QUEUE_MULTIPLIER: Alert queue size multiplier (default: 4)
    - TEST_SHUTDOWN_TIMEOUT: Maximum shutdown wait time (default: 15)
    - TEST_CLEANUP_TIMEOUT: Maximum cleanup wait time (default: 30)

Requirements:
    - Python 3.12 or higher
    - pytest
    - wazuh-dfn package and its dependencies

Usage:
    Run specific test:
        pytest test_performance.py::test_mixed_alerts_performance -v -p no:sugar

    Run with performance markers:
        pytest -v -m performance -p no:sugar

    Run with detailed logging:
        pytest test_performance.py -v --log-cli-level=DEBUG -p no:sugar

Monitoring:
    The test creates two log files:
    - performance_test.log: General test execution logs (INFO level)
    - performance_test_debug.log: Detailed debug information (DEBUG level)

Performance Metrics:
    - Alert processing rate (alerts/second)
    - Queue size and backlog
    - Lost alert count
    - Processing latency
    - Resource utilization

Notes:
    - Tests require sufficient system resources for high-throughput processing
    - Cleanup procedures handle temporary files and system resources
    - Graceful shutdown ensures proper resource release
    - Windows systems may require elevated privileges for some operations
"""

import asyncio
import gc
import json
import logging
import platform
import secrets
import sys
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiofiles
import pytest

from wazuh_dfn.config import MiscConfig, WazuhConfig
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue
from wazuh_dfn.services import WazuhService
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.handlers.syslog_handler import SyslogHandler
from wazuh_dfn.services.handlers.windows_handler import WindowsHandler
from wazuh_dfn.services.kafka_service import KafkaResponse, KafkaService

# Configure logging
logging.getLogger().setLevel(logging.DEBUG)

log_file = "performance_test.log"
log_file_path = Path(log_file)
if log_file_path.exists():
    try:
        log_file_path.unlink()
    except PermissionError:
        # File is in use, use a different name
        import time

        log_file = f"performance_test_{int(time.time())}.log"
        log_file_path = Path(log_file)

file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

debug_log_file = "performance_test_debug.log"
debug_log_file_path = Path(debug_log_file)
if debug_log_file_path.exists():
    try:
        debug_log_file_path.unlink()
    except PermissionError:
        # File is in use, use a different name
        import time

        debug_log_file = f"performance_test_debug_{int(time.time())}.log"
        debug_log_file_path = Path(debug_log_file)

debug_file_handler = logging.FileHandler(debug_log_file)
debug_file_handler.setLevel(logging.DEBUG)
debug_file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]")
)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

root_logger = logging.getLogger()
root_logger.handlers = []
root_logger.addHandler(file_handler)
root_logger.addHandler(debug_file_handler)
root_logger.addHandler(console_handler)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
root_logger.addHandler(stdout_handler)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
LOGGER.propagate = True

LOGGER.info("Performance test logging initialized")
LOGGER.debug("Debug logging initialized")

# Test Parameters
TEST_DURATION = 60
TEST_ALERTS_PER_SECOND = 1000
TEST_NUM_WORKERS = 10
TEST_QUEUE_MULTIPLIER = 4
TEST_SHUTDOWN_TIMEOUT = 15
TEST_CLEANUP_TIMEOUT = 30
TEST_FILE_DELETE_RETRIES = 5
TEST_FILE_DELETE_RETRY_DELAY = 1

MONITORED_EVENT_IDS = ["4625", "4719", "4964", "1102", "4794", "4724", "4697", "4702", "4698", "4672", "4720", "1100"]


def create_windows_alert(event_id: str) -> dict:
    """Create a sample Windows alert."""
    return {
        "timestamp": datetime.now().isoformat(),
        "id": f"test-{secrets.randbelow(9000) + 1000}",
        "agent": {"id": "001", "name": "test-agent"},
        "data": {
            "win": {
                "system": {
                    "eventID": event_id,
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "providerGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
                    "systemTime": datetime.now().isoformat(),
                    "computer": "test-computer",
                    "processID": str(secrets.randbelow(65535)),
                    "threadID": str(secrets.randbelow(65535)),
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
            },
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


def generate_mixed_alerts(count: int) -> list[dict[str, Any]]:
    """Generate a mix of Windows and Fail2ban alerts."""
    alerts = []

    win_monitored_count = count // 3
    win_unmonitored_count = count // 3
    fail2ban_count = count - win_monitored_count - win_unmonitored_count

    for _ in range(win_monitored_count):
        event_id = secrets.choice(MONITORED_EVENT_IDS)
        alerts.append(create_windows_alert(event_id))

    for _ in range(win_unmonitored_count):
        while True:
            event_id = str(secrets.randbelow(9000) + 1000)
            if event_id not in MONITORED_EVENT_IDS:
                break
        alerts.append(create_windows_alert(event_id))

    for _ in range(fail2ban_count):
        alerts.append(create_fail2ban_alert())

    shuffled = list(alerts)
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled


class MockKafkaService(KafkaService):  # Change to inherit from KafkaService
    """Mock Kafka service that counts messages by type."""

    def __init__(self):
        # Skip parent init to avoid actual Kafka connection
        self.windows_count = 0
        self.fail2ban_count = 0
        self.lock = asyncio.Lock()

    # Override other required methods from KafkaService with dummy implementations
    async def start(self) -> None:
        """Start the service."""
        pass

    async def stop(self) -> None:
        """Stop the service."""
        pass

    async def send_message(self, message) -> KafkaResponse | None:
        """Send a message to Kafka."""
        async with self.lock:
            if "win" in message.get("data", {}):
                self.windows_count += 1
            elif message.get("event_format") == "syslog5424-json":
                self.fail2ban_count += 1
        return {"success": True, "topic": "mock-topic"}


class AlertWriter:
    """Writes alerts to file at specified rate."""

    def __init__(self, file_path: str, alerts_per_second: int):
        self.file_path = Path(file_path)
        self.alerts_per_second = alerts_per_second
        self.running = False
        self._stop_event = asyncio.Event()
        self.buffer_size = max(alerts_per_second * 2, 10000)
        self.total_bytes = 0
        self.alert_count = 0
        self.newline_bytes = 0
        self._file = None
        self.newline_size = 2 if platform.system() == "Windows" else 1
        self._lock = asyncio.Lock()
        LOGGER.info(f"Initializing AlertWriter with target rate: {alerts_per_second}/s")
        LOGGER.debug(f"Using newline size: {self.newline_size} bytes")
        self.progress = 0
        self._file_handle = None
        self._task = None

    async def start(self):
        """Start writing alerts to file with better termination handling."""
        LOGGER.info("AlertWriter starting...")
        self.running = True
        self._task = asyncio.create_task(self._run())
        return self._task

    async def _run(self):
        try:
            self._file_handle = await aiofiles.open(self.file_path, "w", encoding="utf-8", buffering=self.buffer_size)
            LOGGER.info("File opened successfully")
            while not self._stop_event.is_set() and self.progress < 60:
                batch_start = time.time()
                await self._write_batch(self._file_handle)
                self.progress += 1
                LOGGER.info(f"Written batch {self.progress}/60")

                elapsed = time.time() - batch_start
                if elapsed < 1.0:
                    await asyncio.sleep(1.0 - elapsed)

            LOGGER.info("AlertWriter completed all batches")
        except asyncio.CancelledError:
            LOGGER.info("AlertWriter task cancelled")
            raise
        except Exception as e:
            LOGGER.error(f"AlertWriter error: {e}")
            if not self._stop_event.is_set():
                raise
        finally:
            await self._close_file()
            self.running = False
            LOGGER.info("AlertWriter stopped")

    async def _write_batch(self, f):
        """Write one second worth of alerts."""
        batch_start = time.time()
        alerts = generate_mixed_alerts(self.alerts_per_second)
        generation_time = time.time() - batch_start

        write_start = time.time()
        batch_content = ""
        for alert in alerts:
            alert_str = json.dumps(alert) + "\n"
            json_bytes = len(alert_str.encode("utf-8"))
            self.total_bytes += json_bytes - 1 + self.newline_size
            self.newline_bytes += self.newline_size
            self.alert_count += 1
            batch_content += alert_str

        if f and not f.closed:
            await f.write(batch_content)
        else:
            raise ValueError("File handle is closed or invalid")

        write_time = time.time() - write_start

        LOGGER.debug(
            f"Batch stats - Generation: {generation_time:.3f}s, "
            f"Writing: {write_time:.3f}s, "
            f"Batch size: {len(alerts)} alerts"
        )

    async def stop(self):
        """Stop writing alerts and close file."""
        self._stop_event.set()
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        await self._close_file()
        self.running = False

    async def _close_file(self):
        """Safely close the file handle."""
        if self._file_handle:
            try:
                await self._file_handle.flush()
                await self._file_handle.close()
                self._file_handle = None
                LOGGER.debug("File handle closed successfully")
            except Exception as e:
                LOGGER.error(f"Error closing file handle: {e}")


async def process_alert(
    alert: dict[str, Any],
    windows_handler: WindowsHandler,
    syslog_handler: SyslogHandler,
    windows_counter: dict[str, int],
    fail2ban_counter: dict[str, int],
):
    """Process a single alert with the appropriate handler."""
    if "win" in alert.get("data", {}):
        await windows_handler.process_alert(alert)
        if alert["data"]["win"]["system"]["eventID"] in MONITORED_EVENT_IDS:
            windows_counter["value"] += 1
    elif "program_name" in alert.get("data", {}) and alert["data"]["program_name"] == "fail2ban.actions":
        await syslog_handler.process_alert(alert)
        fail2ban_counter["value"] += 1
    return True


class ProgressReporter:
    """Reports progress periodically."""

    def __init__(self, alert_queue: AsyncMaxSizeQueue, writer: AlertWriter):
        self.alert_queue = alert_queue
        self.writer = writer
        self.running = False
        self._stop_event = asyncio.Event()
        self._task = None

    async def start(self):
        """Start the reporter."""
        self.running = True
        self._task = asyncio.create_task(self._run())
        return self._task

    async def _run(self):
        last_count = 0
        last_time = time.time()

        while not self._stop_event.is_set():
            await asyncio.sleep(2)
            current_time = time.time()
            current_count = self.writer.alert_count if self.writer else 0

            alerts_per_sec = (current_count - last_count) / (current_time - last_time)
            queue_size = self.alert_queue.qsize()

            LOGGER.info(
                f"Progress - Written: {current_count:,d} alerts, "
                f"Rate: {alerts_per_sec:.1f}/s, "
                f"Queue size: {queue_size:,d}"
            )

            last_count = current_count
            last_time = current_time

    async def stop(self):
        """Stop the reporter."""
        self._stop_event.set()
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        self.running = False


class GracefulExit(SystemExit):  # NOSONAR
    """Custom exception for graceful exit."""

    pass


@pytest.mark.performance(threshold="1000/s", description="Mixed alert processing throughput test")
@pytest.mark.asyncio
async def test_mixed_alerts_performance(caplog):  # noqa: PLR0912 NOSONAR
    """Test processing 1000 mixed alerts/second from file."""
    caplog.set_level(logging.INFO)

    try:
        stop_event = asyncio.Event()
        LOGGER.info("=" * 80)
        LOGGER.info("Starting new performance test run")
        LOGGER.info("=" * 80)

        LOGGER.info("Starting performance test")
        duration = TEST_DURATION
        alerts_per_second = TEST_ALERTS_PER_SECOND
        num_workers = TEST_NUM_WORKERS

        writer = None
        watcher = None
        watcher_task = None
        watcher_shutdown = None
        progress_reporter = None
        alert_queue = None

        alert_file = Path.cwd() / "test_alerts.json"
        if alert_file.exists():
            try:
                gc.collect()
                alert_file.unlink()
            except PermissionError as e:
                LOGGER.warning(f"Could not delete existing file: {e}")
                return

        writer_task = None
        reporter_task = None
        try:
            LOGGER.info(f"Initializing test with {num_workers} workers")
            alert_queue = AsyncMaxSizeQueue(maxsize=alerts_per_second * TEST_QUEUE_MULTIPLIER)
            kafka_service = MockKafkaService()
            wazuh_service = MagicMock(spec=WazuhService)
            wazuh_service.send_event = AsyncMock(return_value=True)
            wazuh_service.send_error = AsyncMock(return_value=True)
            wazuh_service.is_connected = True  # Mock connected state for performance testing

            windows_handler = WindowsHandler(kafka_service, wazuh_service)
            syslog_handler = SyslogHandler(MiscConfig(), kafka_service, wazuh_service)

            windows_count = {"value": 0}
            fail2ban_count = {"value": 0}

            writer = AlertWriter(str(alert_file), alerts_per_second)
            writer_task = await writer.start()

            while writer.progress == 0 and not stop_event.is_set():
                LOGGER.info("Waiting for writer to start processing...")
                await asyncio.sleep(1)

            if stop_event.is_set():
                raise GracefulExit("Test cancelled during startup")

            LOGGER.info("Writer started successfully, configuring watcher...")

            progress_reporter = ProgressReporter(alert_queue, writer)
            reporter_task = await progress_reporter.start()

            config = WazuhConfig()
            config.json_alert_file = str(alert_file)

            watcher_shutdown = asyncio.Event()
            watcher = AlertsWatcherService(config, alert_queue, wazuh_service, watcher_shutdown)
            watcher_task = asyncio.create_task(watcher.start())

            LOGGER.info("Starting alert processing")
            start_time = time.time()
            last_log = start_time
            last_processed = 0

            processed_counters = {"total": 0}

            async def process_alerts():
                while not stop_event.is_set() and time.time() - start_time < duration:
                    try:
                        alert = await asyncio.wait_for(alert_queue.get(), timeout=0.1)
                        await process_alert(alert, windows_handler, syslog_handler, windows_count, fail2ban_count)
                        processed_counters["total"] += 1
                        alert_queue.task_done()
                    except TimeoutError:
                        continue
                    except Exception as e:
                        LOGGER.error(f"Error processing alert: {e}")

            async with asyncio.TaskGroup() as tg:
                _workers = [tg.create_task(process_alerts(), name=f"AlertWorker-{i}") for i in range(num_workers)]

                while time.time() - start_time < duration and not stop_event.is_set():
                    await asyncio.sleep(1.0)

                    current_time = time.time()
                    if current_time - last_log >= 5:
                        elapsed = current_time - last_log
                        processed = processed_counters["total"]
                        current_rate = (processed - last_processed) / elapsed
                        queue_size = alert_queue.qsize()
                        LOGGER.info(
                            f"Progress - Processed: {processed}, "
                            f"Current rate: {current_rate:.1f}/s, "
                            f"Queue size: {queue_size}"
                        )
                        last_log = current_time
                        last_processed = processed

                processed = processed_counters["total"]

            total_time = time.time() - start_time

            actual_rate = processed / total_time
            processed_windows = kafka_service.windows_count
            processed_fail2ban = kafka_service.fail2ban_count

            lost_windows = windows_count["value"] - processed_windows
            lost_fail2ban = fail2ban_count["value"] - processed_fail2ban
            total_lost = lost_windows + lost_fail2ban

            LOGGER.info(f"Test duration: {total_time:.2f} seconds")
            LOGGER.info(f"Processed {processed} alerts")
            LOGGER.info(f"Average rate: {actual_rate:.2f} alerts/second")
            LOGGER.info(
                f"Windows alerts processed: {processed_windows}/{windows_count['value']} (lost: {lost_windows})"
            )
            LOGGER.info(
                f"Fail2ban alerts processed: {processed_fail2ban}/{fail2ban_count['value']} (lost: {lost_fail2ban})"
            )
            LOGGER.info(f"Total lost alerts: {total_lost}")

            actual_file_size = alert_file.stat().st_size
            LOGGER.info(f"Total bytes written (counted): {writer.total_bytes}")
            LOGGER.info(f"Total alerts written: {writer.alert_count}")
            LOGGER.info(f"Total newline bytes: {writer.newline_bytes}")
            LOGGER.info(f"Actual file size: {actual_file_size}")

            content = alert_file.read_bytes()
            last_bytes = content[-10:] if len(content) >= 10 else content
            LOGGER.info(f"Last few bytes (hex): {last_bytes.hex()}")

            actual_newlines = content.count(b"\n")
            LOGGER.info(f"Actual newlines in file: {actual_newlines}")
            LOGGER.info(f"Expected newlines: {writer.alert_count}")

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

            required_threshold = alerts_per_second * 0.95
            percentage_achieved = (actual_rate / alerts_per_second) * 100

            LOGGER.info("Performance metrics:")
            LOGGER.info(f"  - Target: {alerts_per_second} alerts/second")
            LOGGER.info(f"  - Required threshold (95%): {required_threshold:.2f} alerts/second")
            LOGGER.info("  - Actual: %.2f alerts/second (%.1f%% of target)", actual_rate, percentage_achieved)

            assert actual_rate >= required_threshold, (
                f"Processing rate {actual_rate:.2f} below target threshold {required_threshold:.2f} "
                f"({percentage_achieved:.1f}% of {alerts_per_second}/s target). "
                f"Check system load or increase worker count."
            )

            assert (
                processed_windows >= windows_count["value"] * 0.99
            ), f"Lost too many Windows alerts: {lost_windows} ({(lost_windows/windows_count['value'])*100:.1f}%)"
            assert (
                processed_fail2ban >= fail2ban_count["value"] * 0.99
            ), f"Lost too many Fail2ban alerts: {lost_fail2ban} ({(lost_fail2ban/fail2ban_count['value'])*100:.1f}%)"

        finally:
            LOGGER.info("Performing final cleanup")

            tasks_to_cancel = []

            if "writer_task" in locals() and writer_task and not writer_task.done():
                tasks_to_cancel.append(writer_task)

            if "watcher_task" in locals() and watcher_task and not watcher_task.done():
                tasks_to_cancel.append(watcher_task)

            if "reporter_task" in locals() and reporter_task and not reporter_task.done():
                tasks_to_cancel.append(reporter_task)

            for task in tasks_to_cancel:
                task.cancel()

            if tasks_to_cancel:
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks_to_cancel, return_exceptions=True), timeout=5.0)
                except TimeoutError:
                    LOGGER.warning("Some tasks could not be cancelled within timeout")

            if "alert_file" in locals() and alert_file.exists():
                LOGGER.debug("Cleaning up test file...")
                max_retries = TEST_FILE_DELETE_RETRIES
                retry_delay = TEST_FILE_DELETE_RETRY_DELAY

                for attempt in range(max_retries):
                    try:
                        gc.collect()
                        await asyncio.sleep(0.1)

                        alert_file.unlink()
                        LOGGER.info("Test file deleted successfully")
                        break
                    except PermissionError as e:
                        if attempt < max_retries - 1:
                            LOGGER.warning(f"Retry {attempt + 1}/{max_retries} deleting file: {e}")
                            await asyncio.sleep(retry_delay)
                        else:
                            LOGGER.error(f"Failed to delete file after {max_retries} attempts: {e}")
                    except Exception as e:
                        LOGGER.error(f"Unexpected error during file cleanup: {e}")
                        break

            LOGGER.info("Cleanup completed")
    except GracefulExit:
        LOGGER.info("Test cancelled by user")
        assert "initiating graceful shutdown" in caplog.text
