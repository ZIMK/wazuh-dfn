import pytest

from wazuh_dfn.services.file_queue import FileQueue


@pytest.fixture
def test_file(tmp_path):
    """Create a temporary test file and cleanup after"""
    file_path = tmp_path / "test.log"
    with open(file_path, "wb") as f:
        f.write(b"initial content\n")
    yield file_path
    # Cleanup
    try:
        if file_path.exists():
            file_path.unlink()
    except PermissionError:
        pass  # Ignore if file is locked


def test_basic_read(test_file):
    """Test basic file reading without rotation"""
    queue = FileQueue(str(test_file))
    assert queue.open()
    content = queue.read(100)
    assert content == b"initial content\n"
    queue.close()


def test_missing_file(tmp_path):
    """Test handling of missing file"""
    non_existent = tmp_path / "missing.log"
    queue = FileQueue(str(non_existent))

    # Should handle non-existent file gracefully
    assert not queue.open()
    assert queue.read(100) is None
    queue.close()
