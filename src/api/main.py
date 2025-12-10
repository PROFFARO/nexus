import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import router, manager
from .log_watcher import LogWatcher

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexus-api")

# Define log files to watch
BASE_DIR = Path(__file__).parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILES = [
    LOG_DIR / "ftp_log.log",
    LOG_DIR / "ssh_log.log",
    LOG_DIR / "mysql_log.log"
]

watcher = LogWatcher(LOG_FILES)

async def watch_logs():
    """Background task to watch logs and broadcast to WebSockets"""
    logger.info("Starting log watcher background task...")
    async for log_entry in watcher.watch():
        # Here we could filter or transform data before sending
        # For now, just forward the raw log entry
        # We might want to add an event type wrapper
        event = {
            "type": "log_entry",
            "data": log_entry
        }
        await manager.broadcast(event)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    task = asyncio.create_task(watch_logs())
    yield
    # Shutdown
    watcher.stop()
    await task

app = FastAPI(title="Nexus Honeypot API", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for local dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
