import logging
from logging import Logger

from fastapi.testclient import TestClient
from httpx import Response

from app.main import app

logging.basicConfig(level=logging.INFO)
logger: Logger = logging.getLogger(__name__)


def test_root(client: TestClient) -> None:
    response: Response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": app.version}
