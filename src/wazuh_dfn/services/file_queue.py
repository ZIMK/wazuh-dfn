import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class FileQueue:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.fp = None
        self.f_status = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self, tail: bool = False) -> bool:
        if self.fp:
            self.fp.close()

        try:
            self.fp = open(self.file_path, "rb")

            if tail and self.fp.seek(0, os.SEEK_END) == -1:
                logger.error(f"Failed to seek in file {self.file_path}")
                self.fp.close()
                self.fp = None
                return False

            self.f_status = os.fstat(self.fp.fileno())
            return True

        except Exception as e:
            logger.error(f"Error opening file {self.file_path}: {str(e)}")
            if self.fp:
                self.fp.close()
                self.fp = None
            return False

    def read(self) -> Optional[bytes]:
        try:
            return self.fp.read()
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            return None

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None
