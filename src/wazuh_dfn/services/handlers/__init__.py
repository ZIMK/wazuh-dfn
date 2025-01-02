"""Alert handlers package."""

from __future__ import annotations

from .syslog_handler import SyslogHandler
from .windows_handler import WindowsHandler

__version__ = "0.10.1"
__author__ = "Sebastian Wolf (https://github.com/ZIMK/wazuh-dfn)"
__maintainer__ = "Sebastian Wolf"
__all__ = ["SyslogHandler", "WindowsHandler"]
