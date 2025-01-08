import json
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class JSONQueue:
    MAX_SIZE = 65536
    READ_CHUNK_SIZE = 8192

    def __init__(self, alert_prefix: str = ""):
        self.buffer = bytearray()
        self.alert_prefix = alert_prefix.encode("utf-8")
        self.discard_until_prefix = bool(alert_prefix)
        self.brace_count = 0
        self.object_start = 0
        self.error_count = 0
        self.max_error_count = 100
        self.current_batch: List[dict] = []

    def process_json_object(self, json_str: str) -> Optional[dict]:
        try:
            json_obj = json.loads(json_str)
            if not isinstance(json_obj, dict):
                logger.warning("Invalid JSON object type (not a dictionary)")
                return None
            return json_obj
        except json.JSONDecodeError as e:
            self.error_count += 1
            logger.debug(f"JSON decode error: {str(e)}")
            return None

    def add_data(self, new_data: bytes) -> List[dict]:
        # Check for buffer overflow
        if len(self.buffer) + len(new_data) > self.MAX_SIZE:
            logger.warning(f"Buffer would exceed max size ({self.MAX_SIZE}). Discarding old data.")
            self.reset()

        # Handle alert prefix in new data

        prefix_pos = new_data.find(self.alert_prefix)
        if prefix_pos != -1:
            if prefix_pos > 0:
                # Alert prefix found but not at start - process only up to this point
                self.buffer.extend(new_data[:prefix_pos])
                complete_objects = self._process_buffer()
                self.reset()
                # Start fresh with data from prefix position
                self.buffer.extend(new_data[prefix_pos:])
                return complete_objects + self._process_buffer()
            else:
                # Alert prefix found at start - reset and process from here
                self.reset()
                self.buffer.extend(new_data)
        else:
            # No alert prefix found - proceed normally
            self.buffer.extend(new_data)

        return self._process_buffer()

    def _process_buffer(self) -> List[dict]:
        complete_objects = []

        try:
            if self.discard_until_prefix:
                prefix_pos = self.buffer.find(self.alert_prefix)
                if prefix_pos == -1:
                    self.buffer.clear()
                    self.brace_count = 0
                    return []
                else:
                    self.discard_until_prefix = False
                    self.buffer = self.buffer[prefix_pos:]

            decoded_buffer = self.buffer.decode("utf-8")

            # Character-by-character processing for reliable nested JSON handling
            self.brace_count = 0
            i = 0
            while i < len(decoded_buffer):
                char = decoded_buffer[i]
                if char == "{":
                    if self.brace_count == 0:
                        if self.alert_prefix and not decoded_buffer[i:].startswith(self.alert_prefix.decode("utf-8")):
                            i += 1
                            continue
                        self.object_start = i
                    self.brace_count += 1
                elif char == "}":
                    self.brace_count -= 1
                    if self.brace_count == 0:
                        json_str = decoded_buffer[self.object_start : i + 1]
                        json_obj = self.process_json_object(json_str)
                        if json_obj:
                            complete_objects.append(json_obj)
                i += 1

            # Update buffer position if we found complete objects
            if complete_objects:
                self.buffer = self.buffer[len(decoded_buffer[:i].encode("utf-8")) :]
                self.error_count = 0

            if self.error_count >= self.max_error_count:
                logger.warning("Too many parse errors. Resetting buffer.")
                self.reset()

            if len(self.buffer) > self.MAX_SIZE:
                logger.warning("Buffer exceeded max size without matches. Resetting.")
                self.reset()

        except UnicodeDecodeError:
            self.error_count += 1
            logger.debug("UTF-8 decode error in buffer")

        return complete_objects

    def reset(self):
        self.buffer.clear()
        self.brace_count = 0
        self.error_count = 0
        self.discard_until_prefix = bool(self.alert_prefix)
        self.current_batch.clear()
