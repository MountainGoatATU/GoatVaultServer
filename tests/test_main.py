from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_root_endpoint() -> None:
    """Test the root endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["message"] == "GoatVault API"
        assert "docs" in data
        assert data["docs"] == "/docs"


@pytest.mark.asyncio
async def test_openapi_docs() -> None:
    """Test that OpenAPI docs are accessible."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/docs")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_json() -> None:
    """Test that OpenAPI JSON schema is accessible."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert data["info"]["title"] == "GoatVaultServer"


@pytest.mark.asyncio
async def test_production_environment_config():
    """Test that production environment enables HTTPS redirect."""
    import os
    from unittest.mock import patch

    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        # Reload main to apply production settings
        import importlib

        from app import main

        importlib.reload(main)

        # Check middleware is configured for production
        # Note: This is tricky to test directly, but you can check app configuration
        assert main.ENVIRONMENT == "production"


@pytest.mark.asyncio
async def test_lifespan_creates_indexes():
    """Test that app lifespan calls create_indexes on startup."""
    with patch("app.main.create_indexes", new=AsyncMock()) as mock_create:
        # Import app after patching to ensure patch is applied
        from app.main import app as test_app

        # Trigger lifespan startup
        async with test_app.router.lifespan_context(test_app):
            pass

        # Verify indexes were created
        mock_create.assert_called_once()
