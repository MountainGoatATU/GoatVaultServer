from fastapi import FastAPI
from pydantic import BaseModel
from pymongo import AsyncMongoClient
from pymongo import ReturnDocument
from dotenv import load_dotenv
import os

_ = load_dotenv()
app = FastAPI(title="GoatVaultServer", description="A server for GoatVault")
client = AsyncMongoClient(os.environ["MONGODB_URL"])
db = client.get_database(os.environ["DATABASE_NAME"])

vaults = db.get_collection("vaults")
users = db.get_collection("users")


@app.get("/vaults/{user_id}")
def read_vaults(user_id: int):
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}
