"""Services package."""

from __future__ import annotations

from .alerts_service import AlertsService
from .alerts_watcher_service import AlertsWatcherService
from .alerts_worker_service import AlertsWorkerService
from .kafka_service import KafkaService
from .logging_service import LoggingService
from .wazuh_service import WazuhService

__version__ = "0.15.1"
__author__ = "Sebastian Wolf (https://github.com/ZIMK/wazuh-dfn)"
__maintainer__ = "Sebastian Wolf"

__all__ = [
    "AlertsService",
    "AlertsWorkerService",
    "KafkaService",
    "LoggingService",
    "AlertsWatcherService",
    "WazuhService",
]
