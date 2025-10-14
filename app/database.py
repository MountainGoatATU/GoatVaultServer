import os

from dotenv import load_dotenv
from pymongo import AsyncMongoClient

_ = load_dotenv()

client = AsyncMongoClient(os.environ["MONGODB_URL"])
db = client.get_database(os.environ["DATABASE_NAME"])

vaults = db.get_collection("vaults")
users = db.get_collection("users")
