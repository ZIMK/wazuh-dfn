import json
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class JSONQueue:
    def __init__(self, alert_prefix: str = '{"timestamp"'):
        self.buffer = bytearray()
        self.alert_prefix = alert_prefix.encode("utf-8")
        self.error_count = 0
        self.max_error_count = 100
        self._discarded_bytes = 0  # Add counter for discarded bytes

    def _format_bytes_for_log(self, data: bytes, max_len: int = 100) -> str:
        """Format bytes for logging, showing both hex and printable chars."""
        if len(data) > max_len:
            data = data[:max_len] + b"..."
        hex_str = " ".join(f"{b:02x}" for b in data)
        # Replace non-printable chars with dots
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
        return f"hex: [{hex_str}], ascii: [{ascii_str}]"

    def find_json_end(self, text: str, start: int) -> Optional[int]:
        """Find the end position of a JSON object, handling nested structures."""
        brace_count = 0
        in_string = False
        escape_next = False

        for i in range(start, len(text)):
            char = text[i]

            if escape_next:
                escape_next = False
                continue

            if char == "\\":
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return i

        return None

    def find_next_alert(self, text: str) -> Optional[Tuple[int, int]]:
        """Find the next complete alert in text, returns (start, end) positions."""
        start = text.find(self.alert_prefix.decode("utf-8"))
        if start == -1:
            return None

        # Look for nested JSON structures
        end = self.find_json_end(text, start)
        if end is None:
            return None

        # Verify this is a complete, valid JSON object
        try:
            json.loads(text[start : end + 1])
            return (start, end + 1)  # +1 to include the closing brace
        except json.JSONDecodeError:
            # If this JSON is invalid, try finding the next alert after this position
            next_attempt = self.find_next_alert(text[start + 1 :])
            if next_attempt:
                next_start, next_end = next_attempt
                return (start + 1 + next_start, start + 1 + next_end)
            return None

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

    def _get_position_context(self, position: int, initial_size: int) -> str:
        if position < initial_size:
            return f"at beginning portion (position {position} of {initial_size} new bytes)"
        elif position >= len(self.buffer) - initial_size:
            return "at end portion"
        else:
            return "in middle portion (from previous buffer)"

    def add_data(self, new_data: bytes) -> List[dict]:
        initial_size = len(new_data)
        logger.debug(f"Adding {initial_size} bytes to buffer (current buffer size: {len(self.buffer)})")
        self.buffer.extend(new_data)
        self._initial_size = initial_size  # Store for position context
        result = self._process_buffer()
        if result:
            processed_size = sum(len(json.dumps(obj).encode("utf-8")) for obj in result)
            logger.debug(f"Processed {processed_size} bytes into {len(result)} alerts from {initial_size} input bytes")
        return result

    def _process_buffer(self) -> List[dict]:
        complete_objects = []
        discarded_this_round = bytearray()  # Track discarded content
        try:
            # Find valid UTF-8 sequences and build clean buffer
            clean_buffer = bytearray()
            i = 0
            buffer_len = len(self.buffer)

            while i < buffer_len:
                # Check for remaining bytes that might be incomplete UTF-8
                bytes_left = buffer_len - i
                if bytes_left <= 4:  # UTF-8 can be up to 4 bytes
                    # Only keep if potential start of UTF-8 sequence
                    if bytes_left > 1 and (self.buffer[i] & 0xE0) == 0xC0:  # 2-byte sequence
                        self.buffer = self.buffer[i:]
                        break
                    if bytes_left > 2 and (self.buffer[i] & 0xF0) == 0xE0:  # 3-byte sequence
                        self.buffer = self.buffer[i:]
                        break
                    if bytes_left > 3 and (self.buffer[i] & 0xF8) == 0xF0:  # 4-byte sequence
                        self.buffer = self.buffer[i:]
                        break

                # Try to decode current position
                try:
                    # Check UTF-8 sequence length
                    if (self.buffer[i] & 0x80) == 0:  # ASCII
                        length = 1
                    elif (self.buffer[i] & 0xE0) == 0xC0:  # 2-byte sequence
                        length = 2
                    elif (self.buffer[i] & 0xF0) == 0xE0:  # 3-byte sequence
                        length = 3
                    elif (self.buffer[i] & 0xF8) == 0xF0:  # 4-byte sequence
                        length = 4
                    else:  # Invalid UTF-8 start byte
                        context = self._get_position_context(i, self._initial_size)
                        discarded_byte = self.buffer[i : i + 1]
                        discarded_this_round.extend(discarded_byte)
                        logger.warning(
                            f"Invalid UTF-8 start byte {context}: {hex(self.buffer[i])}, "
                            f"content: {self._format_bytes_for_log(discarded_byte)}"
                        )
                        i += 1
                        continue

                    # Try to decode the sequence if we have enough bytes
                    if i + length <= buffer_len:
                        try:
                            char_bytes = self.buffer[i : i + length]
                            char_bytes.decode("utf-8")
                            clean_buffer.extend(char_bytes)
                            i += length
                        except UnicodeDecodeError:
                            # Invalid sequence, skip the first byte
                            discarded_byte = self.buffer[i : i + 1]
                            discarded_this_round.extend(discarded_byte)
                            logger.warning(
                                f"Invalid UTF-8 sequence at {self._get_position_context(i, self._initial_size)}, "
                                f"skipping byte: {self._format_bytes_for_log(discarded_byte)}"
                            )
                            i += 1
                    else:
                        # Not enough bytes for complete sequence
                        self.buffer = self.buffer[i:]
                        break

                except IndexError:
                    # Reached end of buffer
                    if i < buffer_len:
                        self.buffer = self.buffer[i:]
                    break

            # Process the clean buffer
            try:
                decoded = clean_buffer.decode("utf-8")
            except UnicodeDecodeError:
                logger.error("Failed to decode clean buffer")
                self.buffer.clear()
                return complete_objects

            # Process JSON alerts
            current_pos = 0
            while current_pos < len(decoded):
                result = self.find_next_alert(decoded[current_pos:])
                if not result:
                    # Keep remaining data if it might be start of an alert
                    remaining = decoded[current_pos:]
                    if remaining.strip():
                        self.buffer = bytearray(remaining.encode("utf-8"))
                    break

                start, end = result
                abs_start = current_pos + start
                abs_end = current_pos + end

                alert_str = decoded[abs_start:abs_end]
                json_obj = self.process_json_object(alert_str)

                if json_obj:
                    complete_objects.append(json_obj)
                    current_pos = abs_end
                    self.error_count = 0
                else:
                    current_pos = abs_start + 1

            # Handle remaining data
            if current_pos < len(decoded):
                remaining = decoded[current_pos:]
                if remaining.strip():
                    self.buffer = bytearray(remaining.encode("utf-8"))
                else:
                    self.buffer.clear()
            else:
                self.buffer.clear()

            # At the end of processing, log discarded bytes
            if len(discarded_this_round) > 0:
                self._discarded_bytes += len(discarded_this_round)
                logger.warning(
                    f"Discarded {len(discarded_this_round)} bytes in this round "
                    f"(total discarded: {self._discarded_bytes}), "
                    f"content: {self._format_bytes_for_log(discarded_this_round)}"
                )

        except Exception as e:
            logger.error(f"Error processing buffer: {str(e)}")
            if not isinstance(e, UnicodeDecodeError):
                self.error_count += 1
            # Track discarded bytes from complete failure
            discarded_size = len(self.buffer)
            self._discarded_bytes += discarded_size
            logger.warning(
                f"Discarded entire buffer of {discarded_size} bytes due to error, "
                f"content: {self._format_bytes_for_log(bytes(self.buffer))}"
            )

        return complete_objects

    def reset(self):
        self.buffer.clear()
        self.error_count = 0
        self._discarded_bytes = 0
