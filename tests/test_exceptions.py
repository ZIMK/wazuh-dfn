"""Placeholder test for wazuh_dfn.exceptions"""


def test_import_exceptions():
    import importlib

    mod = importlib.import_module("wazuh_dfn.exceptions")
    assert mod is not None
