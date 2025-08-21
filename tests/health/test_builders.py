"""Placeholder test for wazuh_dfn.health.builders"""


def test_import_health_builders():
    import importlib

    mod = importlib.import_module("wazuh_dfn.health.builders")
    assert mod is not None
