"""Placeholder test for wazuh_dfn.health.protocols"""

import importlib


def test_import_health_protocols():
    mod = importlib.import_module("wazuh_dfn.health.protocols")
    assert mod
