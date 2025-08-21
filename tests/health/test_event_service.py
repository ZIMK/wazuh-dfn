"""Placeholder test for wazuh_dfn.health.event_service"""


def test_import_event_service():
    import importlib

    mod = importlib.import_module("wazuh_dfn.health.event_service")
    assert mod is not None
