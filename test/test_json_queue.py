from wazuh_dfn.services.json_queue import JSONQueue


def test_basic_json_parsing():
    queue = JSONQueue()
    input_data = b'{"key": "value"}{"second": "object"}'
    result = queue.add_data(input_data)

    assert len(result) == 2
    assert result[0] == {"key": "value"}
    assert result[1] == {"second": "object"}


def test_alert_prefix_handling():
    queue = JSONQueue(alert_prefix='{"ALERT":')
    input_data = b'{"not_alert": "data"}{"ALERT":{"key": "value"}}{"ALERT":{"second": "object"}}'
    result = queue.add_data(input_data)

    assert len(result) == 2
    assert result[0] == {"ALERT": {"key": "value"}}
    assert result[1] == {"ALERT": {"second": "object"}}


def test_incomplete_json():
    queue = JSONQueue()
    # Send incomplete JSON
    result1 = queue.add_data(b'{"key": "val')
    assert len(result1) == 0

    # Complete the JSON
    result2 = queue.add_data(b'ue"}')
    assert len(result2) == 1
    assert result2[0] == {"key": "value"}


def test_nested_json():
    queue = JSONQueue()
    input_data = b'{"outer": {"inner": "value"}, "array": [1,2,3]}'
    result = queue.add_data(input_data)

    assert len(result) == 1
    assert result[0] == {"outer": {"inner": "value"}, "array": [1, 2, 3]}


def test_invalid_json():
    queue = JSONQueue()
    input_data = b'{"valid": "json"}invalid{not_json}{"valid_again": true}'
    result = queue.add_data(input_data)

    assert len(result) == 2
    assert result[0] == {"valid": "json"}
    assert result[1] == {"valid_again": True}


def test_unicode_handling():
    queue = JSONQueue()
    input_data = '{"unicode": "测试"}'.encode("utf-8")
    result = queue.add_data(input_data)

    assert len(result) == 1
    assert result[0] == {"unicode": "测试"}


def test_multiple_chunks():
    queue = JSONQueue()
    chunk1 = b'{"part": 1}'
    chunk2 = b'{"part": 2}'

    result1 = queue.add_data(chunk1)
    result2 = queue.add_data(chunk2)

    assert len(result1) == 1
    assert len(result2) == 1
    assert result1[0] == {"part": 1}
    assert result2[0] == {"part": 2}
