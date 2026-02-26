import pytest
from fastapi import FastAPI

from app.database import init_db

########################################################################
# App Fixture
########################################################################


@pytest.fixture
def app():
    return FastAPI()


########################################################################
# Database Tests
########################################################################


def test_init_db(app):
    # Ensure the database client and database are initialized
    init_db(app)
    assert hasattr(app.state, "mongo_client")
    assert hasattr(app.state, "db")
    assert app.state.mongo_client is not None
    assert app.state.db is not None
