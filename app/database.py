import os

from dotenv import load_dotenv
from pymongo import AsyncMongoClient

_ = load_dotenv()

client = AsyncMongoClient(os.environ["MONGODB_URL"], uuidRepresentation="standard")
db = client.get_database(os.environ["DATABASE_NAME"])

vault_collection = db.get_collection("vaults")
user_collection = db.get_collection("users")
