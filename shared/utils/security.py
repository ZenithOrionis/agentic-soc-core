from __future__ import annotations

import hmac
import os
from collections.abc import Callable, Iterable
from typing import Awaitable

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from starlette.responses import Response

DEFAULT_DEMO_KEYS = {"", "dev-local-change-me", "local-demo-api-key"}


def is_production() -> bool:
    return os.getenv("ENVIRONMENT", "demo").lower() in {"prod", "production"}


def configured_api_key() -> str:
    return os.getenv("SOC_API_KEY", "local-demo-api-key")


def validate_runtime_security(service_name: str) -> None:
    """Fail closed for production startup if unsafe local defaults are still configured."""
    key = configured_api_key()
    if is_production() and key in DEFAULT_DEMO_KEYS:
        raise RuntimeError(
            f"{service_name} refuses to start in production with the default SOC_API_KEY. "
            "Set a strong per-environment secret through your orchestrator secret store."
        )


def _path_matches(path: str, prefixes: Iterable[str]) -> bool:
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes)


def install_security_middleware(
    app: FastAPI,
    service_name: str,
    public_prefixes: Iterable[str] | None = None,
) -> None:
    """Install API-key auth and conservative security headers.

    Production mode requires X-SOC-API-Key on all routes except explicit health/public paths.
    Demo mode accepts missing keys so local scenario buttons remain frictionless.
    """

    validate_runtime_security(service_name)
    public = set(public_prefixes or [])
    public.update({"/health"})
    if not is_production():
        public.update({"/docs", "/redoc", "/openapi.json"})

    @app.middleware("http")
    async def security_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not _path_matches(request.url.path, public):
            expected = configured_api_key()
            supplied = request.headers.get("X-SOC-API-Key", "") or request.cookies.get("soc_api_key", "")
            if is_production() and not hmac.compare_digest(supplied, expected):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing or invalid SOC API key"},
                    headers={"WWW-Authenticate": "ApiKey"},
                )

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


def auth_headers() -> dict[str, str]:
    return {"X-SOC-API-Key": configured_api_key()}
