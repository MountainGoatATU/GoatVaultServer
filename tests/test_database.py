from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_create_indexes() -> None:
    """Test that create_indexes creates the expected indexes."""
    from app.database import create_indexes, user_collection

    with patch.object(user_collection, "create_indexes", new=AsyncMock()) as mock_create:
        await create_indexes()

        # Verify create_indexes was called
        assert mock_create.called

        # Verify email index was created
        call_args = mock_create.call_args[0][0]
        assert len(call_args) == 1  # One index
        assert call_args[0].document["name"] == "email_unique_idx"
