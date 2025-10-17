import os

from dotenv import load_dotenv
from pymongo import AsyncMongoClient

_ = load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")

if not MONGODB_URL or not DATABASE_NAME:
    raise ValueError(
        "Missing required environment variables: MONGODB_URL and DATABASE_NAME"
    )

client = AsyncMongoClient(MONGODB_URL, uuidRepresentation="standard")
db = client.get_database(DATABASE_NAME)

vault_collection = db.get_collection("vaults")
user_collection = db.get_collection("users")
