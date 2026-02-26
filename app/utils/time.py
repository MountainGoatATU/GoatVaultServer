import logging
from datetime import UTC, datetime, timedelta

_logger = logging.getLogger(__name__)


########################################################################
# Time Helpers
########################################################################


def get_now() -> datetime:
    return datetime.now(UTC)


def get_now_plus_two_minutes() -> datetime:
    return get_now() + timedelta(minutes=2)


def ensure_aware(dt_value: datetime | None) -> datetime | None:
    if dt_value is None:
        _logger.info("Datetime is None")
        return None
    # If Pydantic model instance field (already datetime), preserve/normalize
    try:
        # datetime objects only
        if not isinstance(dt_value, datetime):
            _logger.info(f"Converting datetime {dt_value} to UTC")
            return dt_value.astimezone(UTC)
        if dt_value.tzinfo is None:
            # assume stored naive datetimes are UTC
            return dt_value.replace(tzinfo=UTC)
        # convert to UTC uniformly
        _logger.info(f"Converting datetime {dt_value} to UTC")
        return dt_value.astimezone(UTC)
    except Exception:
        return dt_value

    if dt_value.tzinfo is None:
        # assume stored naive datetimes are UTC
        return dt_value.replace(tzinfo=UTC)
    # convert to UTC uniformly
    _logger.info(f"Converting datetime {dt_value} to UTC")
    return dt_value.astimezone(UTC)
