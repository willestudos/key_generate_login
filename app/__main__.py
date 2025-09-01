import uvicorn

from config.settings import settings


def main() -> None:
    """
        Main function.
    """
    uvicorn.run(
        "app.application:get_app",
        host=settings.host,
        port=settings.fastapi_port,
        reload=settings.reload,
        factory=True
    )


if __name__ == "__main__":
    main()
