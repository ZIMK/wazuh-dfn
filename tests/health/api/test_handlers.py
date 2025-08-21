"""Placeholder test for wazuh_dfn.health.api.handlers"""

import importlib


def test_import_health_api_handlers():
    mod = importlib.import_module("wazuh_dfn.health.api.handlers")
    assert mod
