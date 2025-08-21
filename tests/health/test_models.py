"""Placeholder test for wazuh_dfn.health.models"""

import importlib


def test_import_health_models():
    mod = importlib.import_module("wazuh_dfn.health.models")
    assert mod
