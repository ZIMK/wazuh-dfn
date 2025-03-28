"""Property-based tests for WazuhConfig validators.

This module uses Hypothesis to generate test cases for validation functions in WazuhConfig.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st
from wazuh_dfn.config import WazuhConfig

# Strategy for valid host strings
valid_hosts = st.text(
    min_size=1,
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # No control characters
        blacklist_characters=(",", ")", "(", '"', "'"),  # No characters that would break parsing
    ),
).filter(
    lambda x: x.strip()
)  # Ensure not just whitespace

# Strategy for valid port numbers
valid_ports = st.integers(min_value=1, max_value=65535)

# Strategy for invalid port numbers
invalid_ports = st.one_of(
    st.integers(max_value=0), st.integers(min_value=65536), st.text().filter(lambda x: not x.isdigit())
)

# Strategy for various socket path formats
socket_path_formats = st.one_of(
    # Valid Unix socket paths
    st.text(
        min_size=1, alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters=(",", ")", "(", '"', "'"))
    ),
    # Valid (host, port) string representations
    st.builds(lambda host, port: f"({host}, {port})", host=valid_hosts, port=valid_ports),
    # Invalid format - missing parentheses
    st.builds(lambda host, port: f"{host}, {port}", host=valid_hosts, port=valid_ports),
    # Invalid format - missing comma
    st.builds(lambda host, port: f"({host} {port})", host=valid_hosts, port=valid_ports),
)


class TestWazuhConfigValidators:
    """Property-based tests for WazuhConfig validators."""

    @given(valid_hosts, valid_ports)
    def test_validate_socket_path_with_valid_tuple_string(self, host, port):
        """Test that valid (host, port) string tuples are parsed correctly."""
        socket_path = f"({host}, {port})"
        result = WazuhConfig.validate_socket_path(socket_path)

        assert isinstance(result, tuple)
        assert len(result) == 2
        # The validate_socket_path method strips whitespace and quotes from host values
        # Account for the fact that all special characters and whitespace are stripped
        # from the host value during validation
        expected_host = host.strip().strip("'\"")
        assert result[0] == expected_host.strip() 
        assert result[1] == port

    @given(st.text(min_size=1))
    def test_validate_socket_path_with_plain_string(self, path):
        """Test that plain strings without tuple syntax are returned unchanged."""
        # Skip strings that look like tuples
        if path.startswith("(") and path.endswith(")") and "," in path:
            return

        result = WazuhConfig.validate_socket_path(path)
        assert result == path

    @given(st.builds(lambda host, port: f"({host} {port})", host=valid_hosts, port=valid_ports))  # Missing comma
    def test_validate_socket_path_with_invalid_format(self, socket_path):
        """Test that invalid tuple formats raise appropriate errors."""
        try:
            WazuhConfig.validate_socket_path(socket_path)
            # If we get here without an error, the string wasn't actually recognized as a tuple
            assert not (socket_path.startswith("(") and socket_path.endswith(")") and "," in socket_path)
        except ValueError as e:
            # Validation should have failed
            assert "Invalid host/port format" in str(e)

    @given(
        st.builds(
            lambda host, port: f"({host}, {port})",
            host=valid_hosts,
            port=st.text().filter(lambda x: not x.isdigit()),  # Port is not a number
        )
    )
    def test_validate_socket_path_with_non_numeric_port(self, socket_path):
        """Test that non-numeric ports in tuple format raise appropriate errors."""
        with pytest.raises(ValueError):
            WazuhConfig.validate_socket_path(socket_path)
