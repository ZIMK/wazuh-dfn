"""Placeholder test for wazuh_dfn.service_container"""


def test_import_service_container():
    import importlib

    mod = importlib.import_module("wazuh_dfn.service_container")
    assert mod is not None
