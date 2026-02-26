import json
import logging
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from pydantic import Json
from starlette.middleware.base import BaseHTTPMiddleware

########################################################################
# Configuration
########################################################################

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s - %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)

########################################################################
# Request Logging
########################################################################


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware that shows the full request/response cycle."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log detailed request and response information."""
        body: bytes = await self._get_request_body(request)
        self._log_request(request, body)
        response: Response = await call_next(request)
        self._log_response(response)
        return response

    def _log_request(self, request: Request, body: bytes) -> None:
        """Log request details."""
        logger.info("=" * 80)
        logger.info(f"REQUEST: {request.method} {request.url}")
        logger.info(
            f"Client: {request.client.host}:{request.client.port}"
            if request.client
            else "Client: Unknown"
        )
        logger.info(f"Headers: {json.dumps(dict(request.headers), indent=2)}")

        if body:
            logger.info(f"Body size: {len(body)} bytes")
            self._log_body_content(body)

    def _log_response(self, response: Response) -> None:
        """Log response details."""
        logger.info(f"RESPONSE: Status {response.status_code}")
        logger.info("=" * 80)

    def _log_body_content(self, body: bytes) -> None:
        """Log the content of the request body."""
        try:
            body_json: Json = json.loads(body.decode("utf-8"))
            logger.info(f"Body content:\n{json.dumps(body_json, indent=2)}")
        except Exception as e:
            logger.warning(f"Could not parse body as JSON: {e}")
            logger.info(f"Raw body (first 500 chars): {body[:500]}")

    async def _get_request_body(self, request: Request) -> bytes:
        """Retrieve and restore the request body."""
        body: bytes = await request.body()

        # Restore body for downstream processing
        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body}

        request._receive: Callable = receive
        return body
