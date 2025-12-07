import json
import logging
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware that shows the full request/response cycle."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log detailed request and response information."""
        logger.info("=" * 80)
        logger.info(f"REQUEST: {request.method} {request.url}")
        logger.info(
            f"Client: {request.client.host}:{request.client.port}"
            if request.client
            else "Client: Unknown"
        )
        logger.info(f"Headers: {json.dumps(dict(request.headers), indent=2)}")

        # Read body
        body = await request.body()
        if body:
            logger.info(f"Body size: {len(body)} bytes")
            try:
                body_json = json.loads(body.decode("utf-8"))
                logger.info(f"Body content:\n{json.dumps(body_json, indent=2)}")
            except Exception as e:
                logger.warning(f"Could not parse body as JSON: {e}")
                logger.info(f"Raw body (first 500 chars): {body[:500]}")

            # Restore body for endpoint
            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": body}

            request._receive = receive

        response = await call_next(request)

        logger.info(f"RESPONSE: Status {response.status_code}")
        logger.info("=" * 80)

        return response
