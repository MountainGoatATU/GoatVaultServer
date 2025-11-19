import os

from dotenv import load_dotenv
from pymongo import ASCENDING, AsyncMongoClient, IndexModel
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase

_ = load_dotenv()

MONGODB_URL: str | None = os.getenv("MONGODB_URL")
DATABASE_NAME: str | None = os.getenv("DATABASE_NAME")

if not MONGODB_URL or not DATABASE_NAME:
    raise ValueError("Missing required environment variables: MONGODB_URL and DATABASE_NAME")

client: AsyncMongoClient = AsyncMongoClient(MONGODB_URL, uuidRepresentation="standard")
db: AsyncDatabase = client.get_database(DATABASE_NAME)

vault_collection: AsyncCollection = db.get_collection("vaults")
user_collection: AsyncCollection = db.get_collection("users")


async def create_indexes() -> None:
    """Create database indexes for optimal query performance.

    This function should be called during application startup.
    """
    # User collection indexes
    user_indexes = [
        IndexModel([("email", ASCENDING)], unique=True, name="email_unique_idx"),
    ]
    await user_collection.create_indexes(user_indexes)

    # Vault collection indexes
    vault_indexes = [
        IndexModel([("user_id", ASCENDING)], name="user_id_idx"),
        IndexModel([("user_id", ASCENDING), ("_id", ASCENDING)], name="user_id_vault_id_idx"),
    ]
    await vault_collection.create_indexes(vault_indexes)
