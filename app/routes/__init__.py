"""API route handlers."""

from app.routes.auth_route import init, limiter, register, verify
from app.routes.user_route import delete_user, get_user, update_user

__all__: list[str] = [
    "init",
    "limiter",
    "register",
    "verify",
    "delete_user",
    "get_user",
    "update_user",
]
