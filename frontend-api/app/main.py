from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import os

from models.schemas import AnalyzeRequest
from services.scanner import run_full_scan
import sys
import asyncio

# Fix for Playwright NotImplementedError on Windows with Uvicorn
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

app = FastAPI(title="SecSandbox AI Frontend")

# CORS: Allow Chrome extension and local development to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Chrome extensions use chrome-extension:// origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)


@app.get("/malicious-test", response_class=HTMLResponse)
async def serve_malicious_test(request: Request):
    """
    Simulates a Drive-By Download attack for testing purposes.
    As soon as the page loads, it automatically downloads a dummy file.
    """
    return templates.TemplateResponse(request=request, name="malicious_download.html")

@app.get("/malicious-form", response_class=HTMLResponse)
async def serve_malicious_form(request: Request):
    """
    Simulates a Fake Phishing Login Form for testing purposes.
    Contains password fields and suspicious form actions.
    """
    return templates.TemplateResponse(request=request, name="malicious_form.html")

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/api/analyze")
async def analyze_url(body: AnalyzeRequest):
    """
    Main analysis endpoint.
    Receives a URL, runs the full analysis pipeline, and returns
    the complete security report as JSON.
    """
    try:
        result = await run_full_scan(body.url)
        return result.model_dump()
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Analysis failed: {type(e).__name__}: {e}"}
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
