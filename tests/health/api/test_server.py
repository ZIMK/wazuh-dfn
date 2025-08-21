"""Placeholder test for wazuh_dfn.health.api.server"""

import importlib


def test_import_health_api_server():
    mod = importlib.import_module("wazuh_dfn.health.api.server")
    assert mod
