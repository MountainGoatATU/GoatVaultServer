# database.py
import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from fastapi import FastAPI, Request, Depends

def init_db(app: FastAPI):
    """
    Attach Mongo client and database to FastAPI app state.
    Should be called in FastAPI lifespan.
    """
    app.state.mongo_client = AsyncIOMotorClient(os.environ["MONGODB_URL"])
    app.state.db = app.state.mongo_client[os.environ["DATABASE_NAME"]]

def close_db(app: FastAPI):
    """
    Close the Mongo client when the app shuts down.
    """
    client = getattr(app.state, "mongo_client", None)
    if client:
        client.close()

# Dependency to get user collection
def get_user_collection(request: Request = Depends()) -> AsyncIOMotorCollection:
    """Always works, FastAPI will inject Request automatically."""
    return request.app.state.db["users"]
