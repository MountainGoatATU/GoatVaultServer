from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from supabase import AsyncClient, create_async_client

from app.core.config import settings
from app.main import app


@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="function")
def supabase_client() -> Generator[AsyncClient, None]:
    super_client = create_async_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    yield super_client
