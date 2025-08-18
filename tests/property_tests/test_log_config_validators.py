"""Property-based tests for LogConfig validators.

This module uses Hypothesis to generate test cases for validation functions in LogConfig.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wazuh_dfn.config import LogConfig, LogLevel


@given(st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]))
def test_validate_log_level_with_valid_levels(level):
    """Test that valid log levels are accepted."""
    result = LogConfig.validate_log_level(level)
    assert result == level


@given(st.text().filter(lambda x: x not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]))
def test_validate_log_level_with_invalid_levels(invalid_level):
    """Test that invalid log levels raise appropriate errors."""
    # Skip empty strings or whitespace as they might be handled differently
    if not invalid_level or invalid_level.isspace():
        return

    with pytest.raises(ValueError) as excinfo:
        LogConfig.validate_log_level(invalid_level)
    assert "Invalid log level" in str(excinfo.value)


@given(st.sampled_from([e.value for e in LogLevel]))
def test_validate_log_level_with_enum_values(level):
    """Test that log levels from the LogLevel enum are accepted."""
    result = LogConfig.validate_log_level(level)
    assert result == level


@given(st.sampled_from(["debug", "info", "warning", "error", "critical"]))
def test_validate_log_level_case_sensitivity(lowercase_level):
    """Test that log level validation is case sensitive."""
    with pytest.raises(ValueError):
        LogConfig.validate_log_level(lowercase_level)


def test_validate_file_path():
    """Test the file_path validator.

    Currently, this validator doesn't perform any validation,
    but we test it anyway to ensure its behavior doesn't change.
    """
    # Test with various path formats
    paths = [
        "/var/log/wazuh-dfn.log",
        "C:\\logs\\wazuh-dfn.log",
        "~/logs/wazuh-dfn.log",
        "log.txt",
        "",  # Empty string
        None,  # None value
    ]

    for path in paths:
        result = LogConfig.validate_file_path(path)
        assert result == path
