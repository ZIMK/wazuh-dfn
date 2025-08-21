"""Tests for the main module."""

from __future__ import annotations

import runpy


def test_main_execution(mocker):
    """Test main execution."""
    main_mock = mocker.patch("wazuh_dfn.main.main")

    runpy.run_module("wazuh_dfn.__main__", run_name="__main__")
    main_mock.assert_called_once()
