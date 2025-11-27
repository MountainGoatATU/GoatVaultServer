import json
import logging
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log request details including body content for debugging."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request details and handle the request."""
        # Log basic request info
        logger.info(f"→ {request.method} {request.url.path}")
        logger.info(f"  Headers: {dict(request.headers)}")

        # Read and log the request body
        body = await request.body()
        if body:
            try:
                # Try to parse as JSON for pretty printing
                body_json = json.loads(body.decode("utf-8"))
                logger.info(f"  Body (JSON): {json.dumps(body_json, indent=2)}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If not JSON or has encoding issues, show as bytes/string
                try:
                    body_str = body.decode("utf-8")
                    logger.info(f"  Body (text): {body_str}")
                except UnicodeDecodeError:
                    logger.info(f"  Body (bytes, length={len(body)}): {body[:100]}...")

            # Important: Store the body so the endpoint can read it
            async def receive():
                return {"type": "http.request", "body": body}

            request._receive = receive

        # Process the request
        response = await call_next(request)

        # Log response status
        logger.info(f"← {request.method} {request.url.path} - Status: {response.status_code}")

        return response


class DetailedRequestLoggingMiddleware(BaseHTTPMiddleware):
    """More detailed logging middleware that shows the full request/response cycle."""

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
            async def receive():
                return {"type": "http.request", "body": body}

            request._receive = receive

        response = await call_next(request)

        logger.info(f"RESPONSE: Status {response.status_code}")
        logger.info("=" * 80)

        return response
