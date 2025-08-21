"""Placeholder test for wazuh_dfn.health.api.rate_limiter"""

import importlib


def test_import_health_api_rate_limiter():
    mod = importlib.import_module("wazuh_dfn.health.api.rate_limiter")
    assert mod
