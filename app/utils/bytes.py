import base64
import logging

_logger = logging.getLogger(__name__)

########################################################################
# Bytes Helpers
########################################################################


def ensure_bytes(value) -> bytes:
    """Normalize common token-like/byte-like inputs to bytes."""
    _logger.info("Ensuring bytes")

    # memoryview -> bytes
    if isinstance(value, memoryview):
        return bytes(value)

    # bytes/bytearray -> bytes
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    # list of ints -> bytes
    if isinstance(value, list):
        try:
            return bytes(value)
        except Exception as e:
            _logger.info("Cannot convert list to bytes")
            raise TypeError(f"Cannot convert list to bytes: {e}") from e

    # str -> try base64 decode, fall back to utf-8
    if isinstance(value, str):
        try:
            # Accept padded and unpadded base64; base64.b64decode will raise on invalid input
            return base64.b64decode(value, validate=True)
        except Exception:
            _logger.info("Exception while converting string to bytes")
            # fallback to plain utf-8
            return value.encode("utf-8")

    raise TypeError(f"Unsupported type for bytes conversion: {type(value)!r}")
