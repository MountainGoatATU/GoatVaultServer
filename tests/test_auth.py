import pytest
from fastapi import HTTPException, status
from app.auth import verify_api_key


@pytest.mark.asyncio
async def test_verify_api_key_valid():
    """Test that valid API key is accepted."""
    result = await verify_api_key("test-api-key-12345")
    assert result == "test-api-key-12345"


@pytest.mark.asyncio
async def test_verify_api_key_invalid():
    """Test that invalid API key raises HTTPException."""
    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key("wrong-api-key")
    
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Invalid API key"


@pytest.mark.asyncio
async def test_verify_api_key_empty():
    """Test that empty API key raises HTTPException."""
    with pytest.raises(HTTPException) as exc_info:
        await verify_api_key("")
    
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Invalid API key"
