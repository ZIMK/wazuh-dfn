from unittest.mock import patch

import pytest

from wazuh_dfn.services.max_size_queue import AsyncMaxSizeQueue


@pytest.mark.asyncio
async def test_init():
    queue = AsyncMaxSizeQueue(maxsize=5)
    assert queue.maxsize == 5
    assert queue._discarded_count == 0
    assert queue._first_overflow_logged is False
    assert queue._log_threshold == 1  # 10% of 5, minimum 1


@pytest.mark.asyncio
async def test_normal_queue_operations():
    queue = AsyncMaxSizeQueue(maxsize=3)
    await queue.put(1)
    await queue.put(2)
    assert queue.qsize() == 2
    assert await queue.get() == 1
    assert queue.qsize() == 1


@pytest.mark.asyncio
async def test_overflow_behavior():
    queue = AsyncMaxSizeQueue(maxsize=2)
    await queue.put(1)
    await queue.put(2)
    await queue.put(3)  # This should remove 1
    assert queue.qsize() == 2
    assert await queue.get() == 2
    assert await queue.get() == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "maxsize,items",
    [
        (1, range(3)),
        (2, range(5)),
        (10, range(15)),
    ],
)
async def test_overflow_logging(maxsize, items):
    with patch("wazuh_dfn.services.max_size_queue.LOGGER") as mock_logger:
        queue = AsyncMaxSizeQueue(maxsize=maxsize)

        # Fill queue beyond capacity
        for item in items:
            await queue.put(item)

        # Verify logging occurred
        if len(items) > maxsize:
            mock_logger.warning.assert_called()
            assert queue._discarded_count > 0
        else:
            mock_logger.warning.assert_not_called()
            assert queue._discarded_count == 0


@pytest.mark.asyncio
async def test_log_threshold():
    with patch("wazuh_dfn.services.max_size_queue.LOGGER") as mock_logger:
        queue = AsyncMaxSizeQueue(maxsize=100)

        # Log first discarded message
        for i in range(101):
            await queue.put(i)

        # Should have logged exactly once
        assert mock_logger.warning.call_count == 1
        mock_logger.warning.reset_mock()

        # Add more items but not enough to hit threshold
        for i in range(5):
            await queue.put(1000 + i)

        # Should not have logged again
        assert mock_logger.warning.call_count == 0

        # Add enough items to hit threshold
        for i in range(10):
            await queue.put(2000 + i)

        # Should have logged again
        assert mock_logger.warning.call_count == 1


@pytest.mark.asyncio
async def test_queue_overflow():
    """Test that the queue discards oldest items when it reaches maxsize."""
    # Create a queue with a small maxsize
    queue = AsyncMaxSizeQueue(maxsize=2)

    # Fill the queue
    await queue.put("item1")
    await queue.put("item2")

    # Add one more item, should discard oldest
    await queue.put("item3")

    # Check that the oldest item was discarded
    assert await queue.get() == "item2"
    assert await queue.get() == "item3"
    assert queue.empty()
