import logging
from collections.abc import AsyncGenerator
from logging import Logger

import uvicorn
from fastapi import FastAPI
from fastapi.concurrency import asynccontextmanager
from limits.typing import Any
from mangum import Mangum
from uvicorn.config import LOGGING_CONFIG

from app.core.config import settings
from app.routes.auth_route import auth_router
from app.routes.user_route import user_router

logger: Logger = logging.getLogger("uvicorn")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """life span events"""
    try:
        logger.info("lifespan start")
        yield
    finally:
        logger.info("lifespan exit")


# init FastAPI with lifespan
app = FastAPI(lifespan=lifespan, title=settings.PROJECT_NAME)
handler = Mangum(app)


@app.get("/", tags=["root"])
async def root() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


app.router.include_router(router=user_router)
app.router.include_router(router=auth_router)


# Logger
def timestamp_log_config(uvicorn_log_config: dict[str, Any]) -> dict[str, Any]:
    """https://github.com/fastapi/fastapi/discussions/7457#discussioncomment-5565969"""
    datefmt = "%d-%m-%Y %H:%M:%S"
    formatters = uvicorn_log_config["formatters"]
    formatters["default"]["fmt"] = "%(levelprefix)s [%(asctime)s] %(message)s"
    formatters["access"]["fmt"] = (
        '%(levelprefix)s [%(asctime)s] %(client_addr)s - "%(request_line)s" %(status_code)s'
    )
    formatters["access"]["datefmt"] = datefmt
    formatters["default"]["datefmt"] = datefmt
    return uvicorn_log_config


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config=timestamp_log_config(LOGGING_CONFIG))
