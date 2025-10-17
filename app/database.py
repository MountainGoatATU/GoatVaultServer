import os

from dotenv import load_dotenv
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.asynchronous.collection import AsyncCollection

_ = load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")

if not MONGODB_URL or not DATABASE_NAME:
    raise ValueError(
        "Missing required environment variables: MONGODB_URL and DATABASE_NAME"
    )

client: AsyncMongoClient = AsyncMongoClient(MONGODB_URL, uuidRepresentation="standard")
db: AsyncDatabase = client.get_database(DATABASE_NAME)

vault_collection: AsyncCollection = db.get_collection("vaults")
user_collection: AsyncCollection = db.get_collection("users")
