from unittest.mock import PropertyMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.middleware import RequestLoggingMiddleware


@pytest.fixture
def app_with_logging() -> FastAPI:
    """Create a FastAPI app with logging middleware for testing."""
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)  # type: ignore[arg-type]

    @app.get("/test-get")
    async def test_get() -> dict:
        return {"message": "GET success"}

    @app.post("/test-post")
    async def test_post(data: dict) -> dict:
        return {"message": "POST success", "received": data}

    @app.get("/test-no-client")
    async def test_no_client() -> dict:
        return {"message": "No client info"}

    @app.post("/test-binary")
    async def test_binary() -> dict:
        return {"message": "Binary data received"}

    @app.get("/test-error")
    async def test_error() -> None:
        raise ValueError("Test error")

    return app


@pytest.mark.asyncio
async def test_logging_middleware_get_request(app_with_logging: FastAPI) -> None:
    """Test middleware logs GET requests correctly."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.get("/test-get")

            assert response.status_code == 200
            assert response.json() == {"message": "GET success"}

            # Verify logging calls
            assert mock_logger.info.call_count >= 4
            calls = [str(call) for call in mock_logger.info.call_args_list]

            # Check for key log messages
            assert any("REQUEST: GET" in str(call) for call in calls)
            assert any("Client:" in str(call) for call in calls)
            assert any("Headers:" in str(call) for call in calls)
            assert any("RESPONSE: Status 200" in str(call) for call in calls)


@pytest.mark.asyncio
async def test_logging_middleware_post_request_with_json(app_with_logging: FastAPI) -> None:
    """Test middleware logs POST requests with JSON body."""
    test_data = {"username": "testuser", "password": "testpass123"}

    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.post("/test-post", json=test_data)

            assert response.status_code == 200

            # Verify logging calls
            assert mock_logger.info.call_count >= 5
            calls = [str(call) for call in mock_logger.info.call_args_list]

            # Check for request logs
            assert any("REQUEST: POST" in str(call) for call in calls)
            assert any("Body size:" in str(call) for call in calls)
            assert any("Body content:" in str(call) for call in calls)
            assert any("RESPONSE: Status 200" in str(call) for call in calls)


@pytest.mark.asyncio
async def test_logging_middleware_request_without_client(
    app_with_logging: FastAPI,
) -> None:
    """Test middleware handles requests without client info."""
    with (
        patch("app.middleware.logging.logger") as mock_logger,
        patch(
            "starlette.requests.Request.client",
            new_callable=PropertyMock,
        ) as mock_client,
    ):
        mock_client.return_value = None

        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging),
            base_url="http://test",
        ) as client:
            # Make a request
            response = await client.get("/test-no-client")

        assert response.status_code == 200

        # Check that "Client: Unknown" was logged
        assert any(
            "Client: Unknown" in str(call)
            for call in mock_logger.info.call_args_list
        )

@pytest.mark.asyncio
async def test_logging_middleware_invalid_json_body(app_with_logging: FastAPI) -> None:
    """Test middleware handles non-JSON body gracefully."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            # Send invalid JSON (raw bytes)
            response = await client.post(
                "/test-binary",
                content=b"\x80\x81\x82\x83",  # Invalid UTF-8
                headers={"content-type": "application/octet-stream"},
            )

            assert response.status_code == 200

            # Verify warning was logged about JSON parsing
            assert mock_logger.warning.call_count >= 1
            warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
            assert any("Could not parse body as JSON" in str(call) for call in warning_calls)

            # Verify raw body was logged
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any("Raw body" in str(call) for call in info_calls)


@pytest.mark.asyncio
async def test_logging_middleware_large_body(app_with_logging: FastAPI) -> None:
    """Test middleware handles large bodies correctly (logs first 500 chars of non-JSON)."""
    large_data = "A" * 1000  # 1000 character string

    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            # Send non-JSON large body
            response = await client.post(
                "/test-binary", content=large_data.encode(), headers={"content-type": "text/plain"}
            )

            assert response.status_code == 200

            # Verify raw body logging was truncated to 500 chars
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            raw_body_logged = any("Raw body (first 500 chars)" in str(call) for call in info_calls)
            assert raw_body_logged


@pytest.mark.asyncio
async def test_logging_middleware_empty_body(app_with_logging: FastAPI) -> None:
    """Test middleware handles empty body correctly."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.post("/test-post", json={})

            assert response.status_code == 200

            # Verify body size was logged
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any("Body size:" in str(call) for call in info_calls)


@pytest.mark.asyncio
async def test_logging_middleware_no_body(app_with_logging: FastAPI) -> None:
    """Test middleware handles requests with no body (GET request)."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.get("/test-get")

            assert response.status_code == 200

            # Should not log body-related messages for GET
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            # Body size should not be logged for empty bodies
            body_logs = [call for call in info_calls if "Body size:" in str(call)]
            assert len(body_logs) == 0


@pytest.mark.asyncio
async def test_logging_middleware_error_response(app_with_logging: FastAPI) -> None:
    """Test middleware logs errors correctly."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            # This should trigger a 500 error
            #with pytest.raises(Exception):
                #await client.get("/test-error")
            response = await client.get("/test-error")
            
            assert response.status_code == 500
            
            # Verify request was logged
            calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any("REQUEST: GET" in str(call) for call in calls)


@pytest.mark.asyncio
async def test_logging_middleware_headers_formatting(app_with_logging: FastAPI) -> None:
    """Test that headers are properly formatted in logs."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.get(
                "/test-get", headers={"X-Custom-Header": "test-value", "User-Agent": "test-agent"}
            )

            assert response.status_code == 200

            # Find the headers log call
            info_calls = mock_logger.info.call_args_list
            headers_call = None
            for call in info_calls:
                if call.args and "Headers:" in str(call.args[0]):
                    headers_call = call
                    break

            assert headers_call is not None
            # Verify JSON formatting was attempted
            assert "Headers:" in str(headers_call)


@pytest.mark.asyncio
async def test_logging_middleware_preserves_request_body(app_with_logging: FastAPI) -> None:
    """Test that middleware properly restores request body for endpoint."""
    test_data = {"key": "value", "number": 42}

    with patch("app.middleware.logging.logger"):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.post("/test-post", json=test_data)

            assert response.status_code == 200
            result = response.json()
            # Verify endpoint received the data correctly
            assert result["received"] == test_data


@pytest.mark.asyncio
async def test_logging_middleware_response_status_codes(app_with_logging: FastAPI) -> None:
    """Test middleware logs various response status codes."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            # Test successful response
            response = await client.get("/test-get")
            assert response.status_code == 200

            # Find response status log
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any("RESPONSE: Status 200" in str(call) for call in info_calls)

            # Test 404
            mock_logger.reset_mock()
            response = await client.get("/nonexistent")
            assert response.status_code == 404

            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any("RESPONSE: Status 404" in str(call) for call in info_calls)


@pytest.mark.asyncio
async def test_logging_middleware_separator_lines(app_with_logging: FastAPI) -> None:
    """Test that middleware logs separator lines for readability."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.get("/test-get")

            assert response.status_code == 200

            # Check for separator lines (80 '=' characters)
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            separator_calls = [call for call in info_calls if "=" * 80 in str(call)]
            # Should have at least 2 separators (start and end)
            assert len(separator_calls) >= 2


@pytest.mark.asyncio
async def test_logging_middleware_with_query_parameters(app_with_logging: FastAPI) -> None:
    """Test middleware logs requests with query parameters correctly."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            response = await client.get("/test-get?param1=value1&param2=value2")

            assert response.status_code == 200

            # Check that full URL with query params was logged
            info_calls = [str(call) for call in mock_logger.info.call_args_list]
            assert any(
                "param1=value1" in str(call) and "param2=value2" in str(call) for call in info_calls
            )


@pytest.mark.asyncio
async def test_logging_middleware_json_parse_exception(app_with_logging: FastAPI) -> None:
    """Test specific JSON parsing exception handling."""
    with patch("app.middleware.logging.logger") as mock_logger:
        async with AsyncClient(
            transport=ASGITransport(app=app_with_logging), base_url="http://test"
        ) as client:
            # Send data that will fail JSON parsing
            response = await client.post(
                "/test-binary",
                content=b"not-valid-json-{{{",
                headers={"content-type": "application/json"},
            )

            assert response.status_code == 200

            # Verify specific warning message
            assert mock_logger.warning.called
            warning_call = mock_logger.warning.call_args_list[0]
            assert "Could not parse body as JSON" in str(warning_call)
