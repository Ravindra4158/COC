import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analysis import router as analysis_router
from app.routes.network import router as network_router
from app.routes.recommendations import router as recommendations_router
from app.routes.vulnerabilities import router as vulnerabilities_router

logging.basicConfig(level=logging.INFO)
app = FastAPI(title="CY-02 Vulnerability Prioritization API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(analysis_router)
app.include_router(network_router)
app.include_router(vulnerabilities_router)
app.include_router(recommendations_router)
