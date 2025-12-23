import sys
from pathlib import Path

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent
sys.path.insert(0, str(monorepo_root))

import uvicorn
from config import ApplicationConfig
from src.api.app import create_app

app = create_app(ApplicationConfig)

if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host=ApplicationConfig.API_HOST,
        port=ApplicationConfig.API_PORT,
        reload=True,
        log_level=ApplicationConfig.LOG_LEVEL.lower(),
    )
