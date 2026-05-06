from fastapi import FastAPI

from backend.routers import items

app = FastAPI(
    title="LetsTest Backend",
    description="FastAPI + Pydantic backend for the LetsTest project.",
    version="0.1.0",
)

app.include_router(items.router)


@app.get("/health", tags=["health"])
def health_check():
    """Liveness probe."""
    return {"status": "ok"}
