"""Placeholder test for wazuh_dfn.health.health_service"""

import importlib


def test_import_health_service():
    mod = importlib.import_module("wazuh_dfn.health.health_service")
    assert mod
