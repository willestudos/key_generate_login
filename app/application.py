import logging

from fastapi import FastAPI
from app.config.settings import settings
from app.config.lifetime import startup, shutdown
from app.config.connection import on_application_startup, on_application_shutdown
from app.views.members import router as members
from app.views.oauth import router as oauth
from app.utils.logger import setup_logger
from app.utils.middleware import LoggingMiddleware

setup_logger()
LOGGER = logging.getLogger(__name__)

def get_app() -> FastAPI:
    app = FastAPI(
        title="Api Scammer",
        description="Api para pegar dados via web com suporte OAuth 2.0",
        version=settings.version,
        openapi_url="/openapi.json",
        debug=settings.debug,
        docs_url=None,
        redoc_url=None,
    )
    LOGGER.info("Iniciando aplicação...")
    app.on_event("startup")(startup(on_application_startup))
    app.on_event("shutdown")(shutdown(on_application_shutdown))
    app.add_middleware(LoggingMiddleware)
    app.include_router(members)
    app.include_router(oauth)
    return app

