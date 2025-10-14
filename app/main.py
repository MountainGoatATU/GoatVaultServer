from dotenv import load_dotenv
from fastapi import FastAPI

from app.routes import user_route, vault_route

_ = load_dotenv()
app = FastAPI(title="GoatVaultServer", description="A server for GoatVault")

app.include_router(user_route.router, prefix="/v1")
app.include_router(vault_route.router, prefix="/v1")


@app.get("/")
async def root():
    """
    Root endpoint for GoatVault Server.
    """
    return {"message": "GoatVault Root Endpoint"}
