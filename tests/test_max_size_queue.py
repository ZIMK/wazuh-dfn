from unittest.mock import patch

import pytest

from wazuh_dfn.services.max_size_queue import MaxSizeQueue


def test_init():
    queue = MaxSizeQueue(maxsize=5)
    assert queue.maxsize == 5
    assert queue._discarded_count == 0
    assert queue._first_overflow_logged is False
    assert queue._log_threshold == 1  # 10% of 5, minimum 1


def test_normal_queue_operations():
    queue = MaxSizeQueue(maxsize=3)
    queue.put(1)
    queue.put(2)
    assert queue.qsize() == 2
    assert queue.get() == 1
    assert queue.qsize() == 1


def test_overflow_behavior():
    queue = MaxSizeQueue(maxsize=2)
    queue.put(1)
    queue.put(2)
    queue.put(3)  # This should remove 1
    assert queue.qsize() == 2
    assert queue.get() == 2
    assert queue.get() == 3


@pytest.mark.parametrize(
    "maxsize,items",
    [
        (2, range(5)),
        (1, range(3)),
    ],
)
def test_overflow_logging(maxsize, items):
    with patch("wazuh_dfn.services.max_size_queue.LOGGER") as mock_logger:
        queue = MaxSizeQueue(maxsize=maxsize)
        for item in items:
            queue.put(item)

        # First overflow should always be logged
        mock_logger.warning.assert_called()
        assert queue._first_overflow_logged is True


def test_log_threshold():
    with patch("wazuh_dfn.services.max_size_queue.LOGGER") as mock_logger:
        queue = MaxSizeQueue(maxsize=10)
        # Fill queue and overflow 20 times
        for i in range(30):
            queue.put(i)

        # Should log at first overflow and every 10% (1 item) after
        assert mock_logger.warning.call_count >= 3
