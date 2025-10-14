from fastapi import FastAPI
from pydantic import BaseModel
from pymongo import AsyncMongoClient
from pymongo import ReturnDocument
from dotenv import load_dotenv
import os

_ = load_dotenv()
app = FastAPI()
client = AsyncMongoClient(os.environ["MONGODB_URL"])


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}
