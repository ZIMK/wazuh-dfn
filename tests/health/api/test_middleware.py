"""Placeholder test for wazuh_dfn.health.api.middleware"""

import importlib


def test_import_health_api_middleware():
    mod = importlib.import_module("wazuh_dfn.health.api.middleware")
    assert mod
