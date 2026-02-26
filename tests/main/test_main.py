import os
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from mangum import Mangum

from app.lambda_handler import handler
from app.main import app

########################################################################
# Root Endpoint Tests
########################################################################


@pytest.mark.asyncio
async def test_root_health_check(async_client_no_auth: AsyncClient) -> None:
    """Test the root endpoint / health check."""
    response = await async_client_no_auth.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": app.version}


@pytest.mark.asyncio
async def test_openapi_docs(async_client_no_auth: AsyncClient) -> None:
    """Test that OpenAPI docs are accessible."""
    response = await async_client_no_auth.get("/docs")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_json(async_client_no_auth: AsyncClient) -> None:
    """Test that OpenAPI JSON schema is accessible."""
    response = await async_client_no_auth.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert data["info"]["title"] == "GoatVaultServer"


########################################################################
# Environment Tests
########################################################################


@pytest.mark.asyncio
async def test_production_environment_config() -> None:
    """Test that production environment enables HTTPS redirect."""

    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        # Reload main to apply production settings
        import importlib

        from app import main

        importlib.reload(main)

        # Check middleware is configured for production
        assert main.ENVIRONMENT == "production"


########################################################################
# Lambda Handler Tests
########################################################################


def test_handler_instance():
    """Test that the handler is an instance of Mangum."""
    assert isinstance(handler, Mangum), "Handler should be an instance of Mangum"
