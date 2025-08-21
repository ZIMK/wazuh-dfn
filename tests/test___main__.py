"""Placeholder test for wazuh_dfn.__main__"""


def test_import_dunder_main():
    import importlib

    mod = importlib.import_module("wazuh_dfn.__main__")
    assert mod is not None
